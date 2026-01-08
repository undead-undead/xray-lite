mod grpc;
mod h2;
mod server;

pub use grpc::{GrpcHeaders, GrpcMessage, GrpcStatus, GrpcTrailer};
pub use h2::H2Handler;
pub use server::XhttpServer;

use serde::{Deserialize, Serialize};

/// XHTTP 模式
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum XhttpMode {
    /// 流式上传
    StreamUp,
    /// 流式下载
    StreamDown,
    /// 单向流
    StreamOne,
}

impl XhttpMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            XhttpMode::StreamUp => "stream-up",
            XhttpMode::StreamDown => "stream-down",
            XhttpMode::StreamOne => "stream-one",
        }
    }
}

impl std::fmt::Display for XhttpMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// XHTTP 配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XhttpConfig {
    /// 模式
    pub mode: XhttpMode,
    /// 路径
    pub path: String,
    /// Host 头
    pub host: String,
}
