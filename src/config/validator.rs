use anyhow::{anyhow, Result};
use uuid::Uuid;

use super::Config;

pub struct Validator;

impl Validator {
    /// 验证配置的有效性
    pub fn validate(config: &Config) -> Result<()> {
        // 验证入站配置
        if config.inbounds.is_empty() {
            return Err(anyhow!("至少需要一个入站配置"));
        }

        for (idx, inbound) in config.inbounds.iter().enumerate() {
            Self::validate_inbound(inbound, idx)?;
        }

        // 验证出站配置
        if config.outbounds.is_empty() {
            return Err(anyhow!("至少需要一个出站配置"));
        }

        Ok(())
    }

    fn validate_inbound(inbound: &super::Inbound, idx: usize) -> Result<()> {
        // 验证端口
        if inbound.port == 0 {
            return Err(anyhow!("入站 {} 的端口不能为 0", idx));
        }

        // 验证客户端 UUID
        for (client_idx, client) in inbound.settings.clients.iter().enumerate() {
            if Uuid::parse_str(&client.id).is_err() {
                return Err(anyhow!(
                    "入站 {} 的客户端 {} UUID 格式无效: {}",
                    idx,
                    client_idx,
                    client.id
                ));
            }
        }

        // 验证 Reality 设置
        if let Some(reality) = &inbound.stream_settings.reality_settings {
            Self::validate_reality_settings(reality, idx)?;
        }

        // 验证 XHTTP 设置
        if let Some(xhttp) = &inbound.stream_settings.xhttp_settings {
            Self::validate_xhttp_settings(xhttp, idx)?;
        }

        Ok(())
    }

    fn validate_reality_settings(
        reality: &super::RealitySettings,
        inbound_idx: usize,
    ) -> Result<()> {
        // 验证目标地址
        if reality.dest.is_empty() {
            return Err(anyhow!("入站 {} 的 Reality dest 不能为空", inbound_idx));
        }

        // 验证服务器名称
        if reality.server_names.is_empty() {
            return Err(anyhow!(
                "入站 {} 的 Reality serverNames 不能为空",
                inbound_idx
            ));
        }

        // 验证私钥
        if reality.private_key.is_empty() {
            return Err(anyhow!(
                "入站 {} 的 Reality privateKey 不能为空",
                inbound_idx
            ));
        }

        Ok(())
    }

    fn validate_xhttp_settings(xhttp: &super::XhttpSettings, inbound_idx: usize) -> Result<()> {
        // 验证 host
        // 验证 host
        // if xhttp.host.is_empty() {
        //     return Err(anyhow!("入站 {} 的 XHTTP host 不能为空", inbound_idx));
        // }

        // 验证 path
        if xhttp.path.is_empty() {
            return Err(anyhow!("入站 {} 的 XHTTP path 不能为空", inbound_idx));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::*;

    #[test]
    fn test_valid_config() {
        let config = Config {
            inbounds: vec![Inbound {
                protocol: Protocol::Vless,
                listen: "0.0.0.0".to_string(),
                port: 443,
                settings: InboundSettings {
                    clients: vec![Client {
                        id: "b831381d-6324-4d53-ad4f-8cda48b30811".to_string(),
                        flow: "".to_string(),
                        email: "".to_string(),
                    }],
                    decryption: "none".to_string(),
                },
                stream_settings: StreamSettings {
                    network: Network::Tcp,
                    security: Security::Reality,
                    reality_settings: Some(RealitySettings {
                        dest: "www.apple.com:443".to_string(),
                        server_names: vec!["www.apple.com".to_string()],
                        private_key: "test_key".to_string(),
                        public_key: None,
                        short_ids: vec!["0123456789abcdef".to_string()],
                        fingerprint: "chrome".to_string(),
                    }),
                    xhttp_settings: None,
                },
            }],
            outbounds: vec![Outbound {
                protocol: "freedom".to_string(),
                tag: "direct".to_string(),
                settings: None,
            }],
            routing: RoutingConfig::default(),
        };

        assert!(Validator::validate(&config).is_ok());
    }

    #[test]
    fn test_invalid_uuid() {
        let config = Config {
            inbounds: vec![Inbound {
                protocol: Protocol::Vless,
                listen: "0.0.0.0".to_string(),
                port: 443,
                settings: InboundSettings {
                    clients: vec![Client {
                        id: "invalid-uuid".to_string(),
                        flow: "".to_string(),
                        email: "".to_string(),
                    }],
                    decryption: "none".to_string(),
                },
                stream_settings: StreamSettings {
                    network: Network::Tcp,
                    security: Security::None,
                    reality_settings: None,
                    xhttp_settings: None,
                },
            }],
            outbounds: vec![Outbound {
                protocol: "freedom".to_string(),
                tag: "direct".to_string(),
                settings: None,
            }],
            routing: RoutingConfig::default(),
        };

        assert!(Validator::validate(&config).is_err());
    }
}
