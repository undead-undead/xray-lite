use anyhow::{anyhow, Result};
use bytes::{Bytes, BytesMut};
use h2::server::{self, SendResponse};
use hyper::http::{Request, Response, StatusCode};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{debug, info, warn};

use super::XhttpConfig;

/// HTTP/2 处理器
#[derive(Clone)]
pub struct H2Handler {
    config: XhttpConfig,
}

impl H2Handler {
    pub fn new(config: XhttpConfig) -> Self {
        Self { config }
    }

    /// 处理 HTTP/2 连接
    pub async fn handle<T, F, Fut>(&self, stream: T, handler: F) -> Result<()>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        F: Fn(Box<dyn crate::server::AsyncStream>) -> Fut + Clone + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<()>> + Send + 'static,
    {
        info!("开始处理 HTTP/2 连接");

        let mut builder = server::Builder::new();
        builder
            .initial_window_size(4 * 1024 * 1024)
            .max_concurrent_streams(500)
            .max_frame_size(16384);

        let mut connection = builder.handshake(stream).await?;
        debug!("HTTP/2 握手完成");

        while let Some(result) = connection.accept().await {
            match result {
                Ok((request, respond)) => {
                    let config = self.config.clone();
                    let handler = handler.clone();
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_request(config, request, respond, handler).await {
                            warn!("处理请求失败: {}", e);
                        }
                    });
                }
                Err(e) => {
                    warn!("接受请求失败: {}", e);
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
        let path = request.uri().path();
        let method = request.method();

        // 识别客户端类型：Shadowrocket 会发送 application/grpc
        let content_type = request.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        
        let is_grpc = content_type.contains("grpc");
        debug!("收到请求: {} {} (gRPC Mode: {})", method, path, is_grpc);

        if !path.starts_with(&config.path) {
            Self::send_error_response(&mut respond, StatusCode::NOT_FOUND).await?;
            return Ok(());
        }

        match config.mode.as_str() {
            "auto" | "stream-up" | "stream-down" => {
                Self::handle_dual_stream(request, respond, handler, is_grpc).await?;
            }
            "stream-one" => {
                Self::handle_stream_one(request, respond, handler).await?;
            }
            _ => {
                Self::send_error_response(&mut respond, StatusCode::BAD_REQUEST).await?;
            }
        }
        Ok(())
    }

    /// 核心双向流处理逻辑 (支持 Raw 或 gRPC 封装)
    async fn handle_dual_stream<F, Fut>(
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
            .body(())
            .map_err(|e| anyhow!("构建响应失败: {}", e))?;

        let mut send_stream = respond.send_response(response, false)?;
        let (client_io, server_io) = tokio::io::duplex(16384);
        tokio::spawn(handler(Box::new(server_io)));
        let (mut client_read, mut client_write) = tokio::io::split(client_io);

        // --- UP TASK (Client -> VLESS) ---
        let up_task = async move {
            let mut body = request.into_body();
            let mut leftover = BytesMut::new();
            
            while let Some(chunk_result) = body.data().await {
                let chunk = chunk_result?;
                let _ = body.flow_control().release_capacity(chunk.len());
                
                if is_grpc {
                    leftover.extend_from_slice(&chunk);
                    while leftover.len() >= 5 {
                        let msg_len = u32::from_be_bytes([leftover[1], leftover[2], leftover[3], leftover[4]]) as usize;
                        if leftover.len() >= 5 + msg_len {
                            let _ = leftover.split_to(5);
                            let data = leftover.split_to(msg_len);
                            use tokio::io::AsyncWriteExt;
                            client_write.write_all(&data).await?;
                        } else {
                            break; 
                        }
                    }
                } else {
                    use tokio::io::AsyncWriteExt;
                    client_write.write_all(&chunk).await?;
                }
            }
            Ok::<(), anyhow::Error>(())
        };

        // --- DOWN TASK (VLESS -> Client) ---
        let down_task = async move {
            let mut buf = vec![0u8; 16384];
            use tokio::io::AsyncReadExt;
            loop {
                let n = client_read.read(&mut buf).await?;
                if n == 0 { break; }
                
                if is_grpc {
                    // 包装 gRPC 帧头: [0x00][Len 4B]
                    let mut frame = BytesMut::with_capacity(5 + n);
                    frame.extend_from_slice(&[0u8]);
                    frame.extend_from_slice(&(n as u32).to_be_bytes());
                    frame.extend_from_slice(&buf[..n]);
                    send_stream.send_data(frame.freeze(), false)?;
                } else {
                    send_stream.send_data(Bytes::copy_from_slice(&buf[..n]), false)?;
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

        let _ = tokio::join!(up_task, down_task);
        Ok(())
    }

    /// 单向模式处理 (始终使用 Raw)
    async fn handle_stream_one<F, Fut>(
        mut request: Request<h2::RecvStream>,
        mut respond: SendResponse<Bytes>,
        handler: F,
    ) -> Result<()>
    where
        F: Fn(Box<dyn crate::server::AsyncStream>) -> Fut + Clone + Send + 'static,
        Fut: std::future::Future<Output = Result<()>> + Send + 'static,
    {
        let response = Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/octet-stream")
            .body(())
            .map_err(|e| anyhow!("构建响应失败: {}", e))?;

        let mut send_stream = respond.send_response(response, false)?;
        let (client_io, server_io) = tokio::io::duplex(16384);
        tokio::spawn(handler(Box::new(server_io)));
        let (mut client_read, mut client_write) = tokio::io::split(client_io);

        let up_task = async move {
            let mut body = request.body_mut();
            use tokio::io::AsyncWriteExt;
            while let Some(chunk_res) = body.data().await {
                let chunk = chunk_res?;
                let _ = body.flow_control().release_capacity(chunk.len());
                client_write.write_all(&chunk).await?;
            }
            Ok::<(), anyhow::Error>(())
        };

        let down_task = async move {
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

        let _ = tokio::join!(up_task, down_task);
        Ok(())
    }

    async fn send_error_response(
        respond: &mut SendResponse<Bytes>,
        status: StatusCode,
    ) -> Result<()> {
        let response = Response::builder()
            .status(status)
            .body(())
            .map_err(|e| anyhow!("构建错误响应失败: {}", e))?;
        respond.send_response(response, true)?;
        Ok(())
    }
}
