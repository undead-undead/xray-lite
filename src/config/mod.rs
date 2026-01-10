use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

mod validator;
pub use validator::Validator;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub inbounds: Vec<Inbound>,
    pub outbounds: Vec<Outbound>,
    #[serde(default)]
    pub routing: RoutingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inbound {
    pub protocol: Protocol,
    pub listen: String,
    pub port: u16,
    pub settings: InboundSettings,
    #[serde(rename = "streamSettings")]
    pub stream_settings: StreamSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Vless,
    Vmess,
    Trojan,
    Shadowsocks,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboundSettings {
    pub clients: Vec<Client>,
    #[serde(default = "default_decryption")]
    pub decryption: String,
    #[serde(default)]
    pub sniffing: SniffingConfig,
}

fn default_true() -> bool {
    true
}

/// 流量嗅探配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SniffingConfig {
    /// 是否启用嗅探
    #[serde(default)]
    pub enabled: bool,
    /// 嗅探目标类型
    #[serde(rename = "destOverride", default = "default_dest_override")]
    pub dest_override: Vec<String>,
}

impl Default for SniffingConfig {
    fn default() -> Self {
        Self {
            enabled: false, // 默认关闭
            dest_override: vec!["tls".to_string(), "http".to_string()],
        }
    }
}

fn default_dest_override() -> Vec<String> {
    vec!["tls".to_string(), "http".to_string()]
}

fn default_decryption() -> String {
    "none".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Client {
    pub id: String, // UUID
    #[serde(default)]
    pub flow: String,
    #[serde(default)]
    pub email: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamSettings {
    pub network: Network,
    pub security: Security,
    #[serde(rename = "realitySettings", skip_serializing_if = "Option::is_none")]
    pub reality_settings: Option<RealitySettings>,
    #[serde(rename = "xhttpSettings", skip_serializing_if = "Option::is_none")]
    pub xhttp_settings: Option<XhttpSettings>,
    #[serde(default)]
    pub sockopt: SockOpt,
}

/// Socket 选项配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SockOpt {
    /// TCP Fast Open - 减少握手延迟
    #[serde(rename = "tcpFastOpen", default = "default_true")]
    pub tcp_fast_open: bool,
    /// TCP No Delay (禁用 Nagle 算法) - 减少小包延迟
    #[serde(rename = "tcpNoDelay", default = "default_true")]
    pub tcp_no_delay: bool,
    /// 接受 Proxy Protocol (用于获取真实客户端 IP)
    #[serde(rename = "acceptProxyProtocol", default)]
    pub accept_proxy_protocol: bool,
}

impl Default for SockOpt {
    fn default() -> Self {
        Self {
            tcp_fast_open: true,          // 默认开启
            tcp_no_delay: true,           // 默认开启
            accept_proxy_protocol: false, // 默认关闭
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    Tcp,
    Http,
    Ws,
    Grpc,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Security {
    None,
    Tls,
    Reality,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealitySettings {
    pub dest: String,
    #[serde(rename = "serverNames")]
    pub server_names: Vec<String>,
    #[serde(rename = "privateKey")]
    pub private_key: String,
    #[serde(rename = "publicKey", skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    #[serde(rename = "shortIds")]
    pub short_ids: Vec<String>,
    #[serde(default = "default_fingerprint")]
    pub fingerprint: String,
}

fn default_fingerprint() -> String {
    "chrome".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XhttpSettings {
    #[serde(default = "default_xhttp_mode")]
    pub mode: XhttpMode,
    #[serde(default = "default_path")]
    pub path: String,
    pub host: String,
}

fn default_xhttp_mode() -> XhttpMode {
    XhttpMode::StreamUp
}

fn default_path() -> String {
    "/".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum XhttpMode {
    StreamUp,
    StreamDown,
    StreamOne,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Outbound {
    pub protocol: String,
    pub tag: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settings: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RoutingConfig {
    #[serde(default)]
    pub rules: Vec<RoutingRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingRule {
    #[serde(rename = "type")]
    pub rule_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<Vec<String>>,
    #[serde(rename = "outboundTag")]
    pub outbound_tag: String,
}

impl Config {
    /// 从文件加载配置
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let config: Config = serde_json::from_str(&content)?;

        // 验证配置
        Validator::validate(&config)?;

        Ok(config)
    }

    /// 保存配置到文件
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content = serde_json::to_string_pretty(self)?;
        fs::write(path, content)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_deserialization() {
        let json = r#"
        {
            "inbounds": [{
                "protocol": "vless",
                "listen": "0.0.0.0",
                "port": 443,
                "settings": {
                    "clients": [{
                        "id": "b831381d-6324-4d53-ad4f-8cda48b30811",
                        "flow": ""
                    }],
                    "decryption": "none"
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                        "dest": "www.apple.com:443",
                        "serverNames": ["www.apple.com"],
                        "privateKey": "test_key",
                        "shortIds": ["0123456789abcdef"]
                    }
                }
            }],
            "outbounds": [{
                "protocol": "freedom",
                "tag": "direct"
            }]
        }
        "#;

        let config: Config = serde_json::from_str(json).unwrap();
        assert_eq!(config.inbounds.len(), 1);
        assert_eq!(config.outbounds.len(), 1);
    }
}
