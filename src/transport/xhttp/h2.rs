use anyhow::{anyhow, Result};
use bytes::{Buf, Bytes, BytesMut};
use h2::server::{self, SendResponse};
use hyper::http::{Request, Response, StatusCode};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, Notify};
use tracing::{debug, info, warn};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use once_cell::sync::Lazy;
use rand::{distributions::Alphanumeric, Rng};

use super::XhttpConfig;

/// 全局会话管理器
struct Session {
    to_vless_tx: mpsc::UnboundedSender<Bytes>,
    notify: Arc<Notify>,
}

static SESSIONS: Lazy<Arc<Mutex<HashMap<String, Session>>>> = Lazy::new(|| {
    Arc::new(Mutex::new(HashMap::new()))
});

/// 终极 H2/XHTTP 处理器 (v0.2.74: 带全域静默 Padding)
#[derive(Clone)]
pub struct H2Handler {
    config: XhttpConfig,
}

impl H2Handler {
    pub fn new(config: XhttpConfig) -> Self {
        Self { config }
    }

    /// 生成随机 Padding 字符串，用于模糊 HTTP 头部长度
    fn gen_padding() -> String {
        let mut rng = rand::thread_rng();
        let len = rng.gen_range(64..512); // 随机 64 到 512 字节
        rng.sample_iter(&Alphanumeric)
            .take(len)
            .map(char::from)
            .collect()
    }

    pub async fn handle<T, F, Fut>(&self, stream: T, handler: F) -> Result<()>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        F: Fn(Box<dyn crate::server::AsyncStream>) -> Fut + Clone + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<()>> + Send + 'static,
    {
        debug!("XHTTP: 启动 V74 全域静默填充引擎");

        let mut builder = server::Builder::new();
        builder
            .initial_window_size(524288) // 512KB (Xray default)
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
                            debug!("连接处理闭合: {}", e);
                        }
                    });
                }
                Err(e) => {
                    debug!("H2 连接中断: {}", e);
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

        if method == "GET" {
            Self::handle_xhttp_get(path, respond, handler).await?;
        } else if method == "POST" {
            let user_agent = request.headers().get("user-agent").and_then(|v| v.to_str().ok()).unwrap_or("");
            let is_pc = user_agent.contains("Go-http-client");

            // 等候配对逻辑
            if !is_pc {
                for _ in 0..10 {
                    let found = {
                        let sessions = SESSIONS.lock().unwrap();
                        sessions.contains_key(&path)
                    };
                    if found { break; }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }

            let session_tx = {
                let sessions = SESSIONS.lock().unwrap();
                sessions.get(&path).map(|s| s.to_vless_tx.clone())
            };

            if let Some(tx) = session_tx {
                Self::handle_xhttp_post(request, respond, tx).await?;
            } else {
                let content_type = request.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("");
                let is_grpc = content_type.contains("grpc") && !is_pc;
                Self::handle_standalone(request, respond, handler, is_grpc).await?;
            }
        } else {
            Self::send_error_response(&mut respond, StatusCode::METHOD_NOT_ALLOWED).await?;
        }
        Ok(())
    }

    async fn handle_standalone<F, Fut>(
        mut request: Request<h2::RecvStream>,
        mut respond: SendResponse<Bytes>,
        handler: F,
        is_grpc: bool,
    ) -> Result<()>
    where
        F: Fn(Box<dyn crate::server::AsyncStream>) -> Fut + Clone + Send + 'static,
        Fut: std::future::Future<Output = Result<()>> + Send + 'static,
    {
        let response = Response::builder()
            .status(StatusCode::OK)
            .header("content-type", if is_grpc { "application/grpc" } else { "application/octet-stream" })
            .header("x-padding", Self::gen_padding()) // 注入动态填充
            .body(())
            .unwrap();

        let mut send_stream = respond.send_response(response, false)?;
        let (client_io, server_io) = tokio::io::duplex(65536);
        tokio::spawn(handler(Box::new(server_io)));
        let (mut client_read, mut client_write) = tokio::io::split(client_io);

        // UP
        let up_task = async move {
            let mut body = request.into_body();
            let mut leftover = BytesMut::new();
            use tokio::io::AsyncWriteExt;
            while let Some(chunk_res) = body.data().await {
                let chunk = chunk_res?;
                let _ = body.flow_control().release_capacity(chunk.len());
                if is_grpc {
                    leftover.extend_from_slice(&chunk);
                    while leftover.len() >= 5 {
                        let msg_len = u32::from_be_bytes([leftover[1], leftover[2], leftover[3], leftover[4]]) as usize;
                        if leftover.len() >= 5 + msg_len {
                            let _ = leftover.split_to(5);
                            let data = leftover.split_to(msg_len);
                            client_write.write_all(&data).await?;
                        } else { break; }
                    }
                } else {
                    client_write.write_all(&chunk).await?;
                }
            }
            Ok::<(), anyhow::Error>(())
        };

        // DOWN
        let down_task = async move {
            let mut buf = BytesMut::with_capacity(65536);
            use tokio::io::AsyncReadExt;
            loop {
                if buf.capacity() < 2048 {
                    buf.reserve(65536);
                }
                let n = client_read.read_buf(&mut buf).await?;
                if n == 0 { break; }
                
                if is_grpc {
                    let mut frame = BytesMut::with_capacity(5 + n);
                    frame.extend_from_slice(&[0u8]);
                    frame.extend_from_slice(&(n as u32).to_be_bytes());
                    // copy needed here as we are framing
                    frame.extend_from_slice(&buf[..n]);
                    buf.advance(n);
                    send_stream.send_data(frame.freeze(), false)?;
                } else {
                    // Zero-copy split
                    let chunk = buf.split_to(n).freeze();
                    send_stream.send_data(chunk, false)?;
                }
            }
            if is_grpc {
                let mut trailers = hyper::http::HeaderMap::new();
                trailers.insert("grpc-status", "0".parse().unwrap());
                send_stream.send_trailers(trailers)?;
            } else {
                send_stream.send_data(Bytes::new(), true)?;
            }
            Ok::<(), anyhow::Error>(())
        };

        let _ = tokio::spawn(up_task);
        down_task.await?; 
        Ok(())
    }

    async fn handle_xhttp_get<F, Fut>(
        path: String,
        mut respond: SendResponse<Bytes>,
        handler: F,
    ) -> Result<()>
    where
        F: Fn(Box<dyn crate::server::AsyncStream>) -> Fut + Clone + Send + 'static,
        Fut: std::future::Future<Output = Result<()>> + Send + 'static,
    {
        let (to_vless_tx, mut to_vless_rx) = mpsc::unbounded_channel::<Bytes>();
        let notify = Arc::new(Notify::new());
        {
            let mut sessions = SESSIONS.lock().unwrap();
            sessions.insert(path.clone(), Session { to_vless_tx, notify: notify.clone() });
        }

        let (client_io, server_io) = tokio::io::duplex(65536);
        tokio::spawn(handler(Box::new(server_io)));
        let (mut client_read, mut client_write) = tokio::io::split(client_io);

        let response = Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/octet-stream")
            .header("x-padding", Self::gen_padding()) // 注入动态填充
            .body(())
            .unwrap();
        let mut send_stream = respond.send_response(response, false)?;

        let downstream = async move {
            let mut buf = BytesMut::with_capacity(65536);
            use tokio::io::AsyncReadExt;
            loop {
                if buf.capacity() < 2048 {
                    buf.reserve(65536);
                }
                let n = client_read.read_buf(&mut buf).await?;
                if n == 0 { break; }
                let chunk = buf.split_to(n).freeze();
                send_stream.send_data(chunk, false)?;
            }
            send_stream.send_data(Bytes::new(), true)?;
            Ok::<(), anyhow::Error>(())
        };

        let upstream = async move {
            use tokio::io::AsyncWriteExt;
            while let Some(data) = to_vless_rx.recv().await {
                client_write.write_all(&data).await?;
            }
            Ok::<(), anyhow::Error>(())
        };

        let _ = tokio::spawn(upstream);
        let _ = downstream.await;
        
        {
            let mut sessions = SESSIONS.lock().unwrap();
            sessions.remove(&path);
        }
        notify.notify_waiters();
        Ok(())
    }

    async fn handle_xhttp_post(
        request: Request<h2::RecvStream>,
        mut respond: SendResponse<Bytes>,
        tx: mpsc::UnboundedSender<Bytes>,
    ) -> Result<()> {
        let mut body = request.into_body();
        while let Some(chunk_res) = body.data().await {
            let chunk = chunk_res?;
            let _ = body.flow_control().release_capacity(chunk.len());
            let _ = tx.send(chunk);
        }
        let response = Response::builder()
            .status(StatusCode::OK)
            .header("x-padding", Self::gen_padding()) // 注入动态填充
            .body(())
            .unwrap();
        respond.send_response(response, true)?;
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
