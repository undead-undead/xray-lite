use anyhow::Result;
use bytes::BytesMut;
use std::collections::HashSet;
use uuid::Uuid;

use super::{VlessRequest, VlessResponse};

/// VLESS 协议编解码器
#[derive(Clone)]
pub struct VlessCodec {
    /// 允许的客户端 UUID 集合
    allowed_uuids: HashSet<Uuid>,
}

impl VlessCodec {
    /// 创建新的编解码器
    pub fn new(allowed_uuids: Vec<Uuid>) -> Self {
        Self {
            allowed_uuids: allowed_uuids.into_iter().collect(),
        }
    }

    /// 检查请求完整性 (返回 Ok(Option<usize>) 表示需要/足够的字节数)
    pub fn check_request_completeness(&self, buf: &[u8]) -> Result<Option<usize>> {
        VlessRequest::check_len(buf)
    }

    /// 解码 VLESS 请求
    pub fn decode_request(&self, buf: &mut BytesMut) -> Result<VlessRequest> {
        VlessRequest::decode(buf, &self.allowed_uuids)
    }

    /// 编码 VLESS 响应
    pub fn encode_response(&self, response: &VlessResponse) -> Result<BytesMut> {
        response.encode()
    }
}
