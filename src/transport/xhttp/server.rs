use anyhow::{anyhow, Result};
use tracing::{debug, info};

use super::{XhttpConfig, H2Handler};

/// XHTTP 服务器
#[derive(Clone)]
pub struct XhttpServer {
    h2_handler: H2Handler,
}

impl XhttpServer {
    /// 创建新的 XHTTP 服务器
    pub fn new(config: XhttpConfig) -> Result<Self> {
        // 验证配置
        if config.path.is_empty() {
            return Err(anyhow!("XHTTP path 不能为空"));
        }

        // if config.host.is_empty() {
        //     return Err(anyhow!("XHTTP host 不能为空"));
        // }

        info!("XHTTP 服务器初始化成功");
        debug!("模式: {:?}", config.mode);
        debug!("路径: {}", config.path);
        debug!("Host: {}", config.host);

        let h2_handler = H2Handler::new(config.clone());

        Ok(Self { h2_handler })
    }

    /// 处理传入的连接
    pub async fn accept<T, F, Fut>(&self, stream: T, handler: F) -> Result<()>
    where
        T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
        F: Fn(Box<dyn crate::server::AsyncStream>) -> Fut + Clone + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<()>> + Send + 'static,
    {
        debug!("接收到新的 XHTTP 连接");

        // 使用 H2Handler 处理 HTTP/2 连接
        self.h2_handler.handle(stream, handler).await?;

        Ok(())
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_creation() {
        let config = XhttpConfig {
            mode: XhttpMode::StreamUp,
            path: "/".to_string(),
            host: "www.example.com".to_string(),
        };

        let server = XhttpServer::new(config);
        assert!(server.is_ok());
    }

    #[test]
    fn test_invalid_config() {
        let config = XhttpConfig {
            mode: XhttpMode::StreamUp,
            path: "".to_string(),
            host: "www.example.com".to_string(),
        };
        let server = XhttpServer::new(config);
        assert!(server.is_err());
    }
}
