use anyhow::Result;
use bytes::{BufMut, BytesMut};

use super::request::VLESS_VERSION;

/// VLESS 响应
#[derive(Debug, Clone)]
pub struct VlessResponse {
    /// 协议版本
    pub version: u8,
    /// 附加数据长度
    pub addon_length: u8,
}

impl VlessResponse {
    /// 创建新的响应
    pub fn new() -> Self {
        Self {
            version: VLESS_VERSION,
            addon_length: 0,
        }
    }

    /// 将响应编码为字节流
    pub fn encode(&self) -> Result<BytesMut> {
        let mut buf = BytesMut::new();

        // 写入版本
        buf.put_u8(self.version);

        // 写入附加数据长度
        buf.put_u8(self.addon_length);

        Ok(buf)
    }
}

impl Default for VlessResponse {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_response_encode() {
        let response = VlessResponse::new();
        let buf = response.encode().unwrap();

        assert_eq!(buf.len(), 2);
        assert_eq!(buf[0], VLESS_VERSION);
        assert_eq!(buf[1], 0);
    }
}
