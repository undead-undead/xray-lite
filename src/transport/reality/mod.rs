mod auth;
mod cert_fetch;
mod cert_gen;
pub mod crypto;
mod handshake;
mod server;
pub mod stream;
mod tls;

pub use auth::{RealityAuth, ServerHelloModifier};
pub use cert_fetch::fetch_certificate;
pub use handshake::RealityHandshake;
pub use server::RealityServer;
pub use tls::{ClientHello, ServerHello, TlsRecord};

use serde::{Deserialize, Serialize};

/// Reality 配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealityConfig {
    /// 目标网站地址 (例如: www.apple.com:443)
    pub dest: String,
    /// 服务器名称列表
    pub server_names: Vec<String>,
    /// X25519 私钥 (Base64 编码)
    pub private_key: String,
    /// X25519 公钥 (Base64 编码，可选)
    pub public_key: Option<String>,
    /// Short IDs
    pub short_ids: Vec<String>,
    /// TLS 指纹类型 (chrome, firefox, safari, etc.)
    pub fingerprint: String,
}
pub mod server_rustls;
