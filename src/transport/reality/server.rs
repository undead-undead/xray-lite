use anyhow::{anyhow, Result};
use tokio::net::TcpStream;
use tracing::{debug, info};

use super::{RealityConfig, RealityHandshake};

/// Reality 服务器
#[derive(Clone)]
pub struct RealityServer {
    config: RealityConfig,
    handshake: RealityHandshake,
}

impl RealityServer {
    /// 创建新的 Reality 服务器
    pub fn new(config: RealityConfig) -> Result<Self> {
        // 验证配置
        if config.dest.is_empty() {
            return Err(anyhow!("Reality dest 不能为空"));
        }

        if config.server_names.is_empty() {
            return Err(anyhow!("Reality serverNames 不能为空"));
        }

        if config.private_key.is_empty() {
            return Err(anyhow!("Reality privateKey 不能为空"));
        }

        info!("Reality 服务器初始化成功");
        debug!("目标: {}", config.dest);
        debug!("服务器名称: {:?}", config.server_names);
        debug!("指纹: {}", config.fingerprint);

        let handshake = RealityHandshake::new(config.clone());

        Ok(Self { config, handshake })
    }

    /// 处理传入的 TLS 连接
    pub async fn accept(&self, stream: TcpStream) -> Result<TcpStream> {
        debug!("接收到新的 Reality 连接");

        // 使用 RealityHandshake 执行完整的 TLS 握手
        self.handshake.perform(stream).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> RealityConfig {
        RealityConfig {
            dest: "www.apple.com:443".to_string(),
            server_names: vec!["www.apple.com".to_string(), "*.apple.com".to_string()],
            private_key: "test_private_key_32_bytes_long!".to_string(),
            public_key: Some("test_public_key".to_string()),
            short_ids: vec!["0123456789abcdef".to_string()],
            fingerprint: "chrome".to_string(),
        }
    }

    #[test]
    fn test_server_creation() {
        let config = create_test_config();
        let server = RealityServer::new(config);
        assert!(server.is_ok());
    }
}
