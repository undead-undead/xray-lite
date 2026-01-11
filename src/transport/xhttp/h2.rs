use anyhow::{anyhow, Result};
use bytes::Bytes;
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

        // 高性能配置
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

        if !path.starts_with(&config.path) {
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
            "stream-up" | "stream-down" => {
                Self::handle_stream_up(request, respond, handler).await?;
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

    /// 处理双向流 (VLESS over Raw H2)
    async fn handle_stream_up<F, Fut>(
        mut request: Request<h2::RecvStream>,
        mut respond: SendResponse<Bytes>,
        handler: F,
    ) -> Result<()>
    where
        F: Fn(Box<dyn crate::server::AsyncStream>) -> Fut + Clone + Send + 'static,
        Fut: std::future::Future<Output = Result<()>> + Send + 'static,
    {
        // 采用通用的 octet-stream，避免触发客户端严格的 gRPC 检查
        let response = Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/octet-stream")
            .body(())
            .map_err(|e| anyhow!("构建响应失败: {}", e))?;

        let mut send_stream = respond.send_response(response, false)?;
        let (client_io, server_io) = tokio::io::duplex(16384);
        tokio::spawn(handler(Box::new(server_io)));
        let (mut client_read, mut client_write) = tokio::io::split(client_io);

        // Client -> Server: 直接透传
        let up_task = async move {
            let mut body = request.into_body();
            while let Some(chunk_result) = body.data().await {
                let chunk = chunk_result?;
                let _ = body.flow_control().release_capacity(chunk.len());
                use tokio::io::AsyncWriteExt;
                client_write.write_all(&chunk).await?;
            }
            Ok::<(), anyhow::Error>(())
        };

        // Server -> Client: 直接透传 + Trailer
        let down_task = async move {
            let mut buf = vec![0u8; 16384];
            use tokio::io::AsyncReadExt;
            loop {
                let n = client_read.read(&mut buf).await?;
                if n == 0 { break; }
                send_stream.send_data(Bytes::copy_from_slice(&buf[..n]), false)?;
            }
            // 发送 gRPC Trailers 以满足最小协议闭环
            let mut trailers = hyper::http::HeaderMap::new();
            trailers.insert("grpc-status", "0".parse().unwrap());
            send_stream.send_trailers(trailers)?;
            Ok::<(), anyhow::Error>(())
        };

        let _ = tokio::join!(up_task, down_task);
        Ok(())
    }

    /// 处理下载模式 (复用 handle_stream_up 逻辑)
    async fn handle_stream_down<F, Fut>(
        request: Request<h2::RecvStream>,
        respond: SendResponse<Bytes>,
        handler: F,
    ) -> Result<()>
    where
        F: Fn(Box<dyn crate::server::AsyncStream>) -> Fut + Clone + Send + 'static,
        Fut: std::future::Future<Output = Result<()>> + Send + 'static,
    {
        Self::handle_stream_up(request, respond, handler).await
    }

    /// 处理单向模式
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
