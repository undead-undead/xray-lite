use anyhow::{anyhow, Result};
use bytes::{Buf, BufMut, BytesMut};
use uuid::Uuid;

use super::Address;

/// VLESS 协议版本
pub const VLESS_VERSION: u8 = 0;

/// VLESS 命令类型
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Command {
    /// TCP 连接
    Tcp = 0x01,
    /// UDP 连接
    Udp = 0x02,
    /// Mux (多路复用)
    Mux = 0x03,
}

impl Command {
    pub fn from_u8(value: u8) -> Result<Self> {
        match value {
            0x01 => Ok(Command::Tcp),
            0x02 => Ok(Command::Udp),
            0x03 => Ok(Command::Mux),
            _ => Err(anyhow!("未知的命令类型: {}", value)),
        }
    }
}

/// VLESS 请求
#[derive(Debug, Clone)]
pub struct VlessRequest {
    /// 协议版本
    pub version: u8,
    /// 客户端 UUID
    pub uuid: Uuid,
    /// 命令类型
    pub command: Command,
    /// 目标地址
    pub address: Address,
    /// 附加数据长度
    pub addon_length: u8,
}

impl VlessRequest {
    /// 从字节流解码请求 (支持流式解码)
    /// 返回: Ok(Some(req)) 成功, Ok(None) 数据不足, Err 格式错误
    pub fn decode(buf: &mut BytesMut, allowed_uuids: &[Uuid]) -> Result<Option<Self>> {
        // 1. Check minimal fixed length:
        // Version(1) + UUID(16) + AddonLen(1) = 18 bytes
        if buf.len() < 18 {
            return Ok(None);
        }

        // Peek Version
        let version = buf[0];
        if version != VLESS_VERSION {
            return Err(anyhow!("不支持的 VLESS 版本: {}", version));
        }

        // Peek UUID
        let mut uuid_bytes = [0u8; 16];
        uuid_bytes.copy_from_slice(&buf[1..17]);
        let uuid = Uuid::from_bytes(uuid_bytes);

        if !allowed_uuids.contains(&uuid) {
            return Err(anyhow!("未授权的 UUID: {}", uuid));
        }

        // Peek Addon Length
        let addon_len = buf[17] as usize;

        // 2. Check length after Addon + Command(1)
        // Fixed(18) + Addon(N) + Command(1) = 19 + N
        let offset_command = 18 + addon_len;
        if buf.len() < offset_command + 1 {
            return Ok(None);
        }

        // Peek Command
        let command_byte = buf[offset_command];
        let command = Command::from_u8(command_byte)?;

        // 3. Check Address
        // Address starts at: 18 + addon_len + 1
        let offset_address = offset_command + 1;

        // Use a view of the buffer for address decoding to avoid advancing main buffer
        // BytesMut::split_off is destructive, so we just pass a slice copy or use a temporary cursor logic?
        // Address::decode expects &mut BytesMut and advances it.
        // We can temporarily clone the remaining bytes to check if address is complete.
        // This is slightly inefficient but safe.
        // Optimization: slice buffer without copying?

        let mut addr_buf = BytesMut::from(&buf[offset_address..]);

        let address = match Address::decode(&mut addr_buf)? {
            Some(addr) => addr,
            None => return Ok(None),
        };

        // Calculate total length consumed
        // original len - remaining len in addr_buf = address length
        let addr_len = buf.len() - offset_address - addr_buf.len();
        let total_len = offset_address + addr_len;

        // 4. All good, consume buffer
        buf.advance(total_len);

        Ok(Some(VlessRequest {
            version,
            uuid,
            command,
            address,
            addon_length: addon_len as u8,
        }))
    }

    /// 将请求编码为字节流
    pub fn encode(&self) -> Result<BytesMut> {
        let mut buf = BytesMut::new();

        // 写入版本
        buf.put_u8(self.version);

        // 写入 UUID
        buf.put_slice(self.uuid.as_bytes());

        // 写入附加数据长度 (暂时为 0)
        buf.put_u8(0);

        // 写入命令
        buf.put_u8(self.command as u8);

        // 写入地址
        self.address.encode(&mut buf);

        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_request_encode_decode() {
        let uuid = Uuid::parse_str("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap();
        let request = VlessRequest {
            version: VLESS_VERSION,
            uuid,
            command: Command::Tcp,
            address: Address::Ipv4(Ipv4Addr::new(1, 1, 1, 1), 443),
            addon_length: 0,
        };

        let mut buf = request.encode().unwrap();
        let decoded = VlessRequest::decode(&mut buf, &[uuid]).unwrap();

        assert_eq!(request.version, decoded.version);
        assert_eq!(request.uuid, decoded.uuid);
        assert_eq!(request.command, decoded.command);
        assert_eq!(request.address, decoded.address);
    }

    #[test]
    fn test_unauthorized_uuid() {
        let uuid1 = Uuid::parse_str("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap();
        let uuid2 = Uuid::parse_str("a831381d-6324-4d53-ad4f-8cda48b30812").unwrap();

        let request = VlessRequest {
            version: VLESS_VERSION,
            uuid: uuid1,
            command: Command::Tcp,
            address: Address::Ipv4(Ipv4Addr::new(1, 1, 1, 1), 443),
            addon_length: 0,
        };

        let mut buf = request.encode().unwrap();

        // 使用不同的 UUID 列表进行验证
        let result = VlessRequest::decode(&mut buf, &[uuid2]);
        assert!(result.is_err());
    }
}
