use thiserror::Error;

/// 代理错误类型
#[derive(Error, Debug)]
pub enum ProxyError {
    #[error("配置错误: {0}")]
    ConfigError(String),

    #[error("协议错误: {0}")]
    ProtocolError(String),

    #[error("认证失败: {0}")]
    AuthenticationError(String),

    #[error("网络错误: {0}")]
    NetworkError(String),

    #[error("IO 错误: {0}")]
    IoError(#[from] std::io::Error),

    #[error("UUID 解析错误: {0}")]
    UuidError(#[from] uuid::Error),

    #[error("JSON 解析错误: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("未知错误: {0}")]
    Unknown(String),
}
