use anyhow::{anyhow, Result};
use bytes::{Bytes, BytesMut};
use h2::server::{self, SendResponse};
use hyper::http::{Request, Response, StatusCode};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use once_cell::sync::Lazy;

use super::XhttpConfig;

/// 会话状态，用于焊接 GET 和 POST
struct Session {
    to_server_tx: mpsc::UnboundedSender<Bytes>,
    from_server_rx: Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<Bytes>>>,
}

static SESSIONS: Lazy<Arc<Mutex<HashMap<String, Session>>>> = Lazy::new(|| {
    Arc::new(Mutex::new(HashMap::new()))
});

/// HTTP/2 处理器
#[derive(Clone)]
pub struct H2Handler {
    config: XhttpConfig,
}

impl H2Handler {
    pub fn new(config: XhttpConfig) -> Self {
        Self { config }
    }

    pub async fn handle<T, F, Fut>(&self, stream: T, handler: F) -> Result<()>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        F: Fn(Box<dyn crate::server::AsyncStream>) -> Fut + Clone + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<()>> + Send + 'static,
    {
        debug!("XHTTP: 启动全协议自适应 H2 引擎");

        let mut builder = server::Builder::new();
        builder
            .initial_window_size(4 * 1024 * 1024)
            .max_concurrent_streams(500)
            .max_frame_size(16384);

        let mut connection = builder.handshake(stream).await?;
        
        while let Some(result) = connection.accept().await {
            match result {
                Ok((request, respond)) => {
                    let config = self.config.clone();
                    let handler = handler.clone();
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_request(config, request, respond, handler).await {
                            debug!("请求处理结束: {}", e);
                        }
                    });
                }
                Err(e) => {
                    debug!("H2 连接关闭: {}", e);
                    break;
                }
            }
        }
        Ok(())
    }

    async fn handle_request<F, Fut>(
        config: XhttpConfig,
        request: Request<h2::RecvStream>,
        mut respond: SendResponse<Bytes>,
        handler: F,
    ) -> Result<()>
    where
        F: Fn(Box<dyn crate::server::AsyncStream>) -> Fut + Clone + Send + 'static,
        Fut: std::future::Future<Output = Result<()>> + Send + 'static,
    {
        let path = request.uri().path().to_string();
        let method = request.method();
        
        if !path.starts_with(&config.path) {
            Self::send_error_response(&mut respond, StatusCode::NOT_FOUND).await?;
            return Ok(());
        }

        // --- XHTTP 核心: GET/POST 会话绑定 ---
        // 我们根据路径（通常包含 UUID）来焊接流
        if method == "GET" {
            Self::handle_get_stream(path, respond, handler).await?;
        } else if method == "POST" {
            Self::handle_post_stream(path, request, respond).await?;
        } else {
            Self::send_error_response(&mut respond, StatusCode::METHOD_NOT_ALLOWED).await?;
        }
        Ok(())
    }

    /// 处理下载流 (GET)
    async fn handle_get_stream<F, Fut>(
        path: String,
        mut respond: SendResponse<Bytes>,
        handler: F,
    ) -> Result<()>
    where
        F: Fn(Box<dyn crate::server::AsyncStream>) -> Fut + Clone + Send + 'static,
        Fut: std::future::Future<Output = Result<()>> + Send + 'static,
    {
        let (to_server_tx, mut to_server_rx) = mpsc::unbounded_channel::<Bytes>();
        let (from_server_tx, from_server_rx) = mpsc::unbounded_channel::<Bytes>();
        
        // 注册会话
        {
            let mut sessions = SESSIONS.lock().unwrap();
            sessions.insert(path.clone(), Session {
                to_server_tx,
                from_server_rx: Arc::new(tokio::sync::Mutex::new(from_server_rx)),
            });
        }

        // 构建异步流对接给 VLESS
        let (client_io, server_io) = tokio::io::duplex(65536);
        tokio::spawn(handler(Box::new(server_io)));
        let (mut client_read, mut client_write) = tokio::io::split(client_io);

        // 创建 HTTP 响应
        let response = Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/octet-stream")
            .body(())
            .unwrap();
        let mut send_stream = respond.send_response(response, false)?;

        // VLESS -> Client (通过 GET 响应体)
        let downstream = async move {
            let mut buf = vec![0u8; 16384];
            use tokio::io::AsyncReadExt;
            loop {
                let n = client_read.read(&mut buf).await?;
                if n == 0 { break; }
                send_stream.send_data(Bytes::copy_from_slice(&buf[..n]), false)?;
            }
            send_stream.send_data(Bytes::new(), true)?;
            Ok::<(), anyhow::Error>(())
        };

        // POST -> VLESS (通过焊接的 Channel)
        let upstream = async move {
            use tokio::io::AsyncWriteExt;
            while let Some(data) = to_server_rx.recv().await {
                client_write.write_all(&data).await?;
            }
            Ok::<(), anyhow::Error>(())
        };

        let result = tokio::join!(downstream, upstream);
        
        // 清理会话
        {
            let mut sessions = SESSIONS.lock().unwrap();
            sessions.remove(&path);
        }
        result.0?;
        result.1?;
        Ok(())
    }

    /// 处理上传流 (POST)
    async fn handle_post_stream(
        path: String,
        request: Request<h2::RecvStream>,
        mut respond: SendResponse<Bytes>,
    ) -> Result<()> {
        let session_tx = {
            let sessions = SESSIONS.lock().unwrap();
            sessions.get(&path).map(|s| s.to_server_tx.clone())
        };

        if let Some(tx) = session_tx {
            let mut body = request.into_body();
            while let Some(chunk_res) = body.data().await {
                let chunk = chunk_res?;
                let _ = body.flow_control().release_capacity(chunk.len());
                let _ = tx.send(chunk);
            }
            
            // 响应 200 OK
            let response = Response::builder().status(StatusCode::OK).body(()).unwrap();
            respond.send_response(response, true)?;
        } else {
            // 没有对应的 GET，也把它当做独立的双向流（兼容标准 H2/gRPC）
            // 这里为了极致兼容性，简便起见返回 404 让客户端重试
            Self::send_error_response(&mut respond, StatusCode::NOT_FOUND).await?;
        }
        Ok(())
    }

    async fn send_error_response(
        respond: &mut SendResponse<Bytes>,
        status: StatusCode,
    ) -> Result<()> {
        let response = Response::builder().status(status).body(()).unwrap();
        respond.send_response(response, true)?;
        Ok(())
    }
}
