use anyhow::{anyhow, Result};
use tokio::net::TcpStream;
use tracing::{debug, info};
use base64::{Engine as _, engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}};

use super::RealityConfig;
use super::server_rustls::RealityServerRustls;

/// Reality 服务器 (Wrapper around RealityServerRustls)
#[derive(Clone)]
pub struct RealityServer {
    inner: RealityServerRustls,
}

impl RealityServer {
    /// 创建新的 Reality 服务器
    pub fn new(config: RealityConfig) -> Result<Self> {
        // 验证配置
        if config.dest.is_empty() {
            return Err(anyhow!("Reality dest 不能为空"));
        }

        if config.private_key.is_empty() {
            return Err(anyhow!("Reality privateKey 不能为空"));
        }

        // 解码 private_key (支持 URL-Safe No Padding 和 Standard)
        let private_key_bytes = URL_SAFE_NO_PAD.decode(&config.private_key)
            .or_else(|_| STANDARD.decode(&config.private_key))
            .map_err(|e| anyhow!("Failed to decode Reality private key: {}", e))?;

        if private_key_bytes.len() != 32 {
            return Err(anyhow!("Reality privateKey must be 32 bytes (got {})", private_key_bytes.len()));
        }

        info!("Reality 服务器初始化成功 (Rustls backend)");
        debug!("目标: {}", config.dest);
        debug!("指纹: {}", config.fingerprint);

        let inner = RealityServerRustls::new(private_key_bytes, Some(config.dest.clone()), config.short_ids.clone())?;

        Ok(Self { inner })
    }

    /// 处理传入的 TLS 连接
    pub async fn accept(&self, stream: TcpStream) -> Result<tokio_rustls::server::TlsStream<super::server_rustls::PrefixedStream<TcpStream>>> {
        // 使用 Sniff-and-Dispatch 逻辑
        self.inner.accept(stream).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> RealityConfig {
        RealityConfig {
            dest: "www.apple.com:443".to_string(),
            server_names: vec!["www.apple.com".to_string()],
            // 32 bytes of 'A' in base64
            private_key: "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=".to_string(),
            public_key: None,
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
