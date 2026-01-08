use bytes::{BufMut, Bytes, BytesMut};

/// gRPC 消息格式
///
/// gRPC 使用 Length-Prefixed-Message 格式:
/// [Compressed-Flag(1 byte)][Message-Length(4 bytes)][Message]
pub struct GrpcMessage {
    pub compressed: bool,
    pub data: Vec<u8>,
}

impl GrpcMessage {
    /// 创建新的 gRPC 消息
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            compressed: false,
            data,
        }
    }

    /// 编码为 gRPC 格式
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(5 + self.data.len());

        // Compressed flag (0 = not compressed, 1 = compressed)
        buf.put_u8(if self.compressed { 1 } else { 0 });

        // Message length (big-endian)
        buf.put_u32(self.data.len() as u32);

        // Message data
        buf.put_slice(&self.data);

        buf.freeze()
    }

    /// 从字节流解码
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 5 {
            return None;
        }

        let compressed = data[0] != 0;
        let length = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;

        if data.len() < 5 + length {
            return None;
        }

        let message_data = data[5..5 + length].to_vec();

        Some(Self {
            compressed,
            data: message_data,
        })
    }

    /// 创建空的 gRPC 结束消息
    pub fn empty() -> Bytes {
        Bytes::from_static(&[0, 0, 0, 0, 0])
    }
}

/// gRPC 头部构建器
pub struct GrpcHeaders {
    headers: Vec<(String, String)>,
}

impl GrpcHeaders {
    /// 创建新的 gRPC 头部
    pub fn new() -> Self {
        Self {
            headers: Vec::new(),
        }
    }

    /// 添加标准 gRPC 头部
    pub fn with_grpc_defaults(mut self) -> Self {
        self.headers
            .push(("content-type".to_string(), "application/grpc".to_string()));
        self.headers
            .push(("grpc-encoding".to_string(), "identity".to_string()));
        self.headers
            .push(("grpc-accept-encoding".to_string(), "gzip".to_string()));
        self
    }

    /// 添加自定义头部
    pub fn add_header(mut self, key: String, value: String) -> Self {
        self.headers.push((key, value));
        self
    }

    /// 构建 HTTP/2 响应头部
    pub fn build(&self) -> Vec<(String, String)> {
        self.headers.clone()
    }
}

impl Default for GrpcHeaders {
    fn default() -> Self {
        Self::new()
    }
}

/// gRPC 状态码
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u32)]
pub enum GrpcStatus {
    Ok = 0,
    Cancelled = 1,
    Unknown = 2,
    InvalidArgument = 3,
    DeadlineExceeded = 4,
    NotFound = 5,
    AlreadyExists = 6,
    PermissionDenied = 7,
    ResourceExhausted = 8,
    FailedPrecondition = 9,
    Aborted = 10,
    OutOfRange = 11,
    Unimplemented = 12,
    Internal = 13,
    Unavailable = 14,
    DataLoss = 15,
    Unauthenticated = 16,
}

impl GrpcStatus {
    /// 转换为字符串
    pub fn as_str(&self) -> &'static str {
        match self {
            GrpcStatus::Ok => "0",
            GrpcStatus::Cancelled => "1",
            GrpcStatus::Unknown => "2",
            GrpcStatus::InvalidArgument => "3",
            GrpcStatus::DeadlineExceeded => "4",
            GrpcStatus::NotFound => "5",
            GrpcStatus::AlreadyExists => "6",
            GrpcStatus::PermissionDenied => "7",
            GrpcStatus::ResourceExhausted => "8",
            GrpcStatus::FailedPrecondition => "9",
            GrpcStatus::Aborted => "10",
            GrpcStatus::OutOfRange => "11",
            GrpcStatus::Unimplemented => "12",
            GrpcStatus::Internal => "13",
            GrpcStatus::Unavailable => "14",
            GrpcStatus::DataLoss => "15",
            GrpcStatus::Unauthenticated => "16",
        }
    }

    /// 获取状态消息
    pub fn message(&self) -> &'static str {
        match self {
            GrpcStatus::Ok => "OK",
            GrpcStatus::Cancelled => "Cancelled",
            GrpcStatus::Unknown => "Unknown",
            GrpcStatus::InvalidArgument => "Invalid argument",
            GrpcStatus::DeadlineExceeded => "Deadline exceeded",
            GrpcStatus::NotFound => "Not found",
            GrpcStatus::AlreadyExists => "Already exists",
            GrpcStatus::PermissionDenied => "Permission denied",
            GrpcStatus::ResourceExhausted => "Resource exhausted",
            GrpcStatus::FailedPrecondition => "Failed precondition",
            GrpcStatus::Aborted => "Aborted",
            GrpcStatus::OutOfRange => "Out of range",
            GrpcStatus::Unimplemented => "Unimplemented",
            GrpcStatus::Internal => "Internal error",
            GrpcStatus::Unavailable => "Unavailable",
            GrpcStatus::DataLoss => "Data loss",
            GrpcStatus::Unauthenticated => "Unauthenticated",
        }
    }
}

/// gRPC Trailer (结束标记)
pub struct GrpcTrailer {
    pub status: GrpcStatus,
    pub message: Option<String>,
}

impl GrpcTrailer {
    /// 创建成功的 trailer
    pub fn ok() -> Self {
        Self {
            status: GrpcStatus::Ok,
            message: None,
        }
    }

    /// 创建错误的 trailer
    pub fn error(status: GrpcStatus, message: String) -> Self {
        Self {
            status,
            message: Some(message),
        }
    }

    /// 构建 trailer 头部
    pub fn build(&self) -> Vec<(String, String)> {
        let mut headers = vec![("grpc-status".to_string(), self.status.as_str().to_string())];

        if let Some(msg) = &self.message {
            headers.push(("grpc-message".to_string(), msg.clone()));
        }

        headers
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grpc_message_encode_decode() {
        let data = b"Hello, gRPC!".to_vec();
        let msg = GrpcMessage::new(data.clone());

        let encoded = msg.encode();
        assert_eq!(encoded.len(), 5 + data.len());

        let decoded = GrpcMessage::decode(&encoded).unwrap();
        assert_eq!(decoded.data, data);
        assert!(!decoded.compressed);
    }

    #[test]
    fn test_grpc_empty_message() {
        let empty = GrpcMessage::empty();
        assert_eq!(empty.len(), 5);
        assert_eq!(&empty[..], &[0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_grpc_headers() {
        let headers = GrpcHeaders::new().with_grpc_defaults().build();

        assert!(headers
            .iter()
            .any(|(k, v)| k == "content-type" && v == "application/grpc"));
        assert!(headers
            .iter()
            .any(|(k, v)| k == "grpc-encoding" && v == "identity"));
    }

    #[test]
    fn test_grpc_status() {
        assert_eq!(GrpcStatus::Ok.as_str(), "0");
        assert_eq!(GrpcStatus::NotFound.as_str(), "5");
        assert_eq!(GrpcStatus::Internal.message(), "Internal error");
    }

    #[test]
    fn test_grpc_trailer() {
        let trailer = GrpcTrailer::ok();
        let headers = trailer.build();

        assert!(headers.iter().any(|(k, v)| k == "grpc-status" && v == "0"));
    }
}
