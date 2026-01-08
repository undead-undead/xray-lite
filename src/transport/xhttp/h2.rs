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
    pub async fn handle<T>(&self, stream: T) -> Result<()>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
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
                    
                    // 为每个请求生成一个任务
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_request(config, request, respond).await {
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
    async fn handle_request(
        config: XhttpConfig,
        request: Request<h2::RecvStream>,
        mut respond: SendResponse<Bytes>,
    ) -> Result<()> {
        let path = request.uri().path();
        let method = request.method();

        debug!("收到请求: {} {}", method, path);

        // 验证路径
        if path != config.path {
            warn!("路径不匹配: {} != {}", path, config.path);
            Self::send_error_response(&mut respond, StatusCode::NOT_FOUND).await?;
            return Ok(());
        }

        // 验证 Host 头
        if let Some(host) = request.headers().get("host") {
            if let Ok(host_str) = host.to_str() {
                if host_str != config.host {
                    warn!("Host 不匹配: {} != {}", host_str, config.host);
                    Self::send_error_response(&mut respond, StatusCode::BAD_REQUEST).await?;
                    return Ok(());
                }
            }
        }

        // 根据模式处理
        match config.mode.as_str() {
            "stream-up" => {
                Self::handle_stream_up(request, respond).await?;
            }
            "stream-down" => {
                Self::handle_stream_down(request, respond).await?;
            }
            "stream-one" => {
                Self::handle_stream_one(request, respond).await?;
            }
            _ => {
                warn!("未知模式: {}", config.mode);
                Self::send_error_response(&mut respond, StatusCode::BAD_REQUEST).await?;
            }
        }

        Ok(())
    }

    /// 处理 stream-up 模式 (上传流)
    async fn handle_stream_up(
        mut request: Request<h2::RecvStream>,
        mut respond: SendResponse<Bytes>,
    ) -> Result<()> {
        debug!("处理 stream-up 模式");

        // 发送 gRPC 响应头 (伪装)
        let response = Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/grpc")
            .header("grpc-encoding", "identity")
            .header("grpc-accept-encoding", "gzip")
            .body(())
            .map_err(|e| anyhow!("构建响应失败: {}", e))?;

        let mut send_stream = respond.send_response(response, false)?;
        debug!("已发送 gRPC 响应头");

        // 接收客户端上传的数据
        let mut body = request.body_mut();
        let mut total_bytes = 0;

        while let Some(chunk) = body.data().await {
            match chunk {
                Ok(data) => {
                    total_bytes += data.len();
                    debug!("收到数据块: {} 字节", data.len());
                    
                    // 释放流量控制窗口
                    let _ = body.flow_control().release_capacity(data.len());
                    
                    // TODO: 这里应该处理实际的 VLESS 数据
                    // 目前只是接收并丢弃
                }
                Err(e) => {
                    warn!("接收数据失败: {}", e);
                    break;
                }
            }
        }

        info!("stream-up 完成，总共接收: {} 字节", total_bytes);

        // 发送 gRPC 结束标记
        send_stream.send_data(Bytes::from_static(b"\x00\x00\x00\x00\x00"), true)?;

        Ok(())
    }

    /// 处理 stream-down 模式 (下载流)
    async fn handle_stream_down(
        _request: Request<h2::RecvStream>,
        mut respond: SendResponse<Bytes>,
    ) -> Result<()> {
        debug!("处理 stream-down 模式");

        // 发送 gRPC 响应头
        let response = Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/grpc")
            .header("grpc-encoding", "identity")
            .body(())
            .map_err(|e| anyhow!("构建响应失败: {}", e))?;

        let mut send_stream = respond.send_response(response, false)?;

        // TODO: 这里应该发送实际的 VLESS 数据
        // 目前发送一个空的 gRPC 消息
        send_stream.send_data(Bytes::from_static(b"\x00\x00\x00\x00\x00"), true)?;

        info!("stream-down 完成");
        Ok(())
    }

    /// 处理 stream-one 模式 (单向流)
    async fn handle_stream_one(
        _request: Request<h2::RecvStream>,
        mut respond: SendResponse<Bytes>,
    ) -> Result<()> {
        debug!("处理 stream-one 模式");

        // 发送简单的 HTTP/2 响应
        let response = Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/octet-stream")
            .body(())
            .map_err(|e| anyhow!("构建响应失败: {}", e))?;

        let mut send_stream = respond.send_response(response, false)?;

        // TODO: 发送实际数据
        send_stream.send_data(Bytes::from_static(b"OK"), true)?;

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
