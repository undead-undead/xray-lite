use anyhow::{anyhow, Result};
use bytes::Bytes;
use h2::server::{self, SendResponse};
use hyper::http::{Request, Response, StatusCode};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{debug, info, warn, error};

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

        // 创建 HTTP/2 服务器连接 (高性能配置)
        let mut builder = server::Builder::new();
        builder
            .initial_window_size(4 * 1024 * 1024)
            .max_concurrent_streams(500)
            .max_frame_size(16384);

        let mut connection = builder.handshake(stream).await?;
        debug!("HTTP/2 握手完成");

        // 处理传入的请求流
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

        info!("HTTP/2 连接关闭");
        Ok(())
    }

    // ... (handle_request)
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

        debug!("收到请求: {} {}", method, path);

        if !path.starts_with(&config.path) {
            warn!("路径不匹配: {} (Config: {})", path, config.path);
            Self::send_error_response(&mut respond, StatusCode::NOT_FOUND).await?;
            return Ok(());
        }

        match config.mode.as_str() {
            "auto" => {
                if method == "POST" {
                    Self::handle_stream_up(request, respond, handler).await?;
                } else {
                    Self::handle_stream_down(request, respond, handler).await?;
                }
            }
            "stream-up" => {
                Self::handle_stream_up(request, respond, handler).await?;
            }
            "stream-down" => {
                Self::handle_stream_down(request, respond, handler).await?;
            }
            "stream-one" => {
                Self::handle_stream_one(request, respond, handler).await?;
            }
            _ => {
                warn!("未知模式: {}", config.mode);
                Self::send_error_response(&mut respond, StatusCode::BAD_REQUEST).await?;
            }
        }

        Ok(())
    }

    /// 处理 stream-up 模式 (双向流 - VLESS via gRPC)
    async fn handle_stream_up<F, Fut>(
        mut request: Request<h2::RecvStream>,
        mut respond: SendResponse<Bytes>,
        handler: F,
    ) -> Result<()>
    where
        F: Fn(Box<dyn crate::server::AsyncStream>) -> Fut + Clone + Send + 'static,
        Fut: std::future::Future<Output = Result<()>> + Send + 'static,
    {
        debug!("处理 stream-up 模式 (gRPC Framing Enabled)");

        let response = Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/grpc")
            .header("grpc-encoding", "identity")
            .body(())
            .map_err(|e| anyhow!("构建响应失败: {}", e))?;

        let mut send_stream = respond.send_response(response, false)?;
        let (client_io, server_io) = tokio::io::duplex(16384);
        tokio::spawn(handler(Box::new(server_io)));
        let (mut client_read, mut client_write) = tokio::io::split(client_io);

        // --- UP TASK (Client -> Server) ---
        // 解析 gRPC L-P-M 帧并提取 Raw VLESS 数据
        let up_task = async move {
            let mut body = request.into_body();
            let mut leftover = bytes::BytesMut::new();
            let mut is_grpc_framed = None; // Sniffing state

            while let Some(chunk_result) = body.data().await {
                let chunk = chunk_result?;
                let _ = body.flow_control().release_capacity(chunk.len());
                leftover.extend_from_slice(&chunk);

                // Sniffing: First byte of first chunk
                if is_grpc_framed.is_none() && leftover.len() >= 5 {
                    if leftover[0] == 0 { // Compressed flag is usually 0
                        is_grpc_framed = Some(true);
                        debug!("Sniffed: gRPC Framed Client (Shadowrocket/iOS)");
                    } else {
                        is_grpc_framed = Some(false);
                        debug!("Sniffed: Raw H2 Client (PC/Xray)");
                    }
                }

                if let Some(true) = is_grpc_framed {
                    // Unwrap gRPC Frames
                    while leftover.len() >= 5 {
                        let msg_len = u32::from_be_bytes([leftover[1], leftover[2], leftover[3], leftover[4]]) as usize;
                        if leftover.len() >= 5 + msg_len {
                            let _ = leftover.split_to(5);
                            let data = leftover.split_to(msg_len);
                            use tokio::io::AsyncWriteExt;
                            client_write.write_all(&data).await?;
                        } else {
                            break; // Wait for full message
                        }
                    }
                } else if let Some(false) = is_grpc_framed {
                    // Traditional Raw Pipe
                    use tokio::io::AsyncWriteExt;
                    client_write.write_all(&leftover).await?;
                    leftover.clear();
                } else if leftover.len() > 0 && leftover.len() < 5 {
                    // Need more to sniff
                }
            }
            Ok::<(), anyhow::Error>(())
        };

        // --- DOWN TASK (Server -> Client) ---
        // 将 Raw VLESS 数据包装进 gRPC L-P-M 帧
        let down_task = async move {
            let mut buf = vec![0u8; 16000]; // Max allowed payload in one H2 FRAME usually
            use tokio::io::AsyncReadExt;
            loop {
                let n = client_read.read(&mut buf).await?;
                if n == 0 { break; }
                
                // Wrap in gRPC Frame: [0x00][Len 4B][Data]
                let mut frame = bytes::BytesMut::with_capacity(5 + n);
                frame.extend_from_slice(&[0u8]); // No compression
                frame.extend_from_slice(&(n as u32).to_be_bytes());
                frame.extend_from_slice(&buf[..n]);
                
                send_stream.send_data(frame.freeze(), false)?;
            }
            
            // 发送 gRPC Trailers 以完成请求周期
            let mut trailers = hyper::http::HeaderMap::new();
            trailers.insert("grpc-status", "0".parse().unwrap());
            trailers.insert("grpc-message", "OK".parse().unwrap());
            send_stream.send_trailers(trailers)?;
            
            Ok::<(), anyhow::Error>(())
        };

        let _ = tokio::join!(up_task, down_task);
        debug!("stream-up 完成");
        Ok(())
    }

    /// 处理 stream-down 模式 (下载流 - VLESS via gRPC)
    async fn handle_stream_down<F, Fut>(
        request: Request<h2::RecvStream>,
        mut respond: SendResponse<Bytes>,
        handler: F,
    ) -> Result<()>
    where
        F: Fn(Box<dyn crate::server::AsyncStream>) -> Fut + Clone + Send + 'static,
        Fut: std::future::Future<Output = Result<()>> + Send + 'static,
    {
        // 实际上与 stream-up 逻辑几乎一样，只是方向意图不同，但 VLESS 是双向的
        Self::handle_stream_up(request, respond, handler).await
    }

    /// 处理 stream-one 模式 (单向流 - VLESS via Raw Body)
    async fn handle_stream_one<F, Fut>(
        mut request: Request<h2::RecvStream>,
        mut respond: SendResponse<Bytes>,
        handler: F,
    ) -> Result<()>
    where
        F: Fn(Box<dyn crate::server::AsyncStream>) -> Fut + Clone + Send + 'static,
        Fut: std::future::Future<Output = Result<()>> + Send + 'static,
    {
        debug!("处理 stream-one 模式");

        let response = Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/octet-stream")
            .body(())
            .map_err(|e| anyhow!("构建响应失败: {}", e))?;

        let mut send_stream = respond.send_response(response, false)?;
        let (client_io, server_io) = tokio::io::duplex(8192);
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
            let mut buf = vec![0u8; 8192];
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
        info!("stream-one 完成");
        Ok(())
    }

    /// 发送错误响应
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::xhttp::XhttpMode;

    fn create_test_config() -> XhttpConfig {
        XhttpConfig {
            mode: XhttpMode::StreamUp,
            path: "/".to_string(),
            host: "www.example.com".to_string(),
        }
    }

    #[test]
    fn test_h2_handler_creation() {
        let config = create_test_config();
        let _handler = H2Handler::new(config);
    }
}
