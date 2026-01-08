use anyhow::Result;
use bytes::BytesMut;
use uuid::Uuid;

use super::{VlessRequest, VlessResponse};

/// VLESS 协议编解码器
#[derive(Clone)]
pub struct VlessCodec {
    /// 允许的客户端 UUID 列表
    allowed_uuids: Vec<Uuid>,
}

impl VlessCodec {
    /// 创建新的编解码器
    pub fn new(allowed_uuids: Vec<Uuid>) -> Self {
        Self { allowed_uuids }
    }

    /// 解码 VLESS 请求
    pub fn decode_request(&self, buf: &mut BytesMut) -> Result<VlessRequest> {
        VlessRequest::decode(buf, &self.allowed_uuids)
    }

    /// 编码 VLESS 响应
    pub fn encode_response(&self, response: &VlessResponse) -> Result<BytesMut> {
        response.encode()
    }

    /// 验证 UUID 是否在允许列表中
    pub fn validate_uuid(&self, uuid: &Uuid) -> bool {
        self.allowed_uuids.contains(uuid)
    }

    /// 添加允许的 UUID
    pub fn add_uuid(&mut self, uuid: Uuid) {
        if !self.allowed_uuids.contains(&uuid) {
            self.allowed_uuids.push(uuid);
        }
    }

    /// 移除允许的 UUID
    pub fn remove_uuid(&mut self, uuid: &Uuid) -> bool {
        if let Some(pos) = self.allowed_uuids.iter().position(|u| u == uuid) {
            self.allowed_uuids.remove(pos);
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uuid_validation() {
        let uuid1 = Uuid::parse_str("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap();
        let uuid2 = Uuid::parse_str("a831381d-6324-4d53-ad4f-8cda48b30812").unwrap();

        let codec = VlessCodec::new(vec![uuid1]);

        assert!(codec.validate_uuid(&uuid1));
        assert!(!codec.validate_uuid(&uuid2));
    }

    #[test]
    fn test_add_remove_uuid() {
        let uuid1 = Uuid::parse_str("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap();
        let uuid2 = Uuid::parse_str("a831381d-6324-4d53-ad4f-8cda48b30812").unwrap();

        let mut codec = VlessCodec::new(vec![uuid1]);

        // 添加新 UUID
        codec.add_uuid(uuid2);
        assert!(codec.validate_uuid(&uuid2));

        // 移除 UUID
        assert!(codec.remove_uuid(&uuid2));
        assert!(!codec.validate_uuid(&uuid2));
    }
}
