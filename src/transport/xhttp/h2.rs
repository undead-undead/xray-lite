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

        // 创建 HTTP/2 服务器连接
        let mut connection = server::handshake(stream).await?;
        debug!("HTTP/2 握手完成");

        // 处理传入的请求流
        while let Some(result) = connection.accept().await {
            match result {
                Ok((request, respond)) => {
                    let config = self.config.clone();
                    let handler = handler.clone();
                    
                    // 为每个请求生成一个任务
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

    /// 处理单个 HTTP/2 请求
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

        // 验证路径
        if path != config.path {
            warn!("路径不匹配: {} != {}", path, config.path);
            Self::send_error_response(&mut respond, StatusCode::NOT_FOUND).await?;
            return Ok(());
        }

        // 验证 Host 头 (如果配置了 Host)
        if !config.host.is_empty() {
            if let Some(host) = request.headers().get("host") {
                if let Ok(host_str) = host.to_str() {
                    // 简单的 Host 匹配 (不包含端口)
                    let host_only = host_str.split(':').next().unwrap_or(host_str);
                    if host_only != config.host && host_str != config.host {
                        warn!("Host 不匹配: {} != {}", host_str, config.host);
                        Self::send_error_response(&mut respond, StatusCode::BAD_REQUEST).await?;
                        return Ok(());
                    }
                }
            }
        }

        // 根据模式处理
        match config.mode.as_str() {
            "auto" => {
                // 自动选择：根据请求方法判断
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

    /// 处理 stream-up 模式 (上传流 - VLESS via gRPC)
    async fn handle_stream_up<F, Fut>(
        mut request: Request<h2::RecvStream>,
        mut respond: SendResponse<Bytes>,
        handler: F,
    ) -> Result<()>
    where
        F: Fn(Box<dyn crate::server::AsyncStream>) -> Fut + Clone + Send + 'static,
        Fut: std::future::Future<Output = Result<()>> + Send + 'static,
    {
        debug!("处理 stream-up 模式");

        let response = Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/grpc")
            .header("grpc-encoding", "identity")
            .body(())
            .map_err(|e| anyhow!("构建响应失败: {}", e))?;

        let mut send_stream = respond.send_response(response, false)?;
        let (client_io, server_io) = tokio::io::duplex(8192);
        tokio::spawn(handler(Box::new(server_io)));
        let (mut client_read, mut client_write) = tokio::io::split(client_io);

        let mut client_write = client_write;

        let up_task = async move {
            info!("🚀 Up task started - waiting for body data");
            let mut body = request.body_mut();
            let mut buf = bytes::BytesMut::new();
            use tokio::io::AsyncWriteExt;
            
            loop {
                let chunk_future = body.data();
                
                tokio::select! {
                    res = chunk_future => {
                        match res {
                            Some(Ok(chunk)) => {
                                info!("✅ XHTTP 收到数据块: {} 字节", chunk.len());
                                let _ = body.flow_control().release_capacity(chunk.len());
                                
                                if chunk.len() > 0 {
                                    let dump_len = std::cmp::min(chunk.len(), 32);
                                    info!("📦 Hex Dump (Head): {}", hex::encode(&chunk[..dump_len]));
                                }

                                // 直接直通写入管道，不尝试解析 gRPC
                                // 让后端的 VLESS Codec 去处理（如果格式不对会报错并打印数据，这样我们就能看到原始数据了）
                                client_write.write_all(&chunk).await?;
                                info!("➡️ 已转发 {} 字节到 VLESS Handler", chunk.len());
                            }
                            Some(Err(e)) => {
                                error!("❌ 读取 Body 错误: {}", e);
                                break;
                            }
                            None => {
                                info!("🏁 Body stream ended (EOF)");
                                break;
                            }
                        }
                    }
                    _ = tokio::time::sleep(std::time::Duration::from_millis(2000)) => {
                        info!("💤 Up task waiting for data... (2s tick)");
                    }
                }
            }
            info!("Up task finished loop");
            Ok::<(), anyhow::Error>(())
        };

        let down_task = async move {
            let mut buf = vec![0u8; 8192];
            use tokio::io::AsyncReadExt;
            loop {
                let n = client_read.read(&mut buf).await?;
                if n == 0 { break; }
                
                let msg = super::grpc::GrpcMessage::new(buf[..n].to_vec());
                send_stream.send_data(msg.encode(), false)?;
            }
            // 发送 Trailer
            // 简单的 GRPC-Status: 0 trailer 在 send_response 时很难发送，h2 trait 需要 send_trailers
            // 这里我们简化，直接结束流
            send_stream.send_data(Bytes::new(), true)?;
            Ok::<(), anyhow::Error>(())
        };

        let _ = tokio::join!(up_task, down_task);
        info!("stream-up 完成");
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
