use anyhow::{anyhow, Result};
use bytes::{Buf, BytesMut};
use uuid::Uuid;

use super::Address;

pub const VLESS_VERSION: u8 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Tcp = 0x01,
    Udp = 0x02,
    Mux = 0x03,
}

impl Command {
    pub fn from_u8(b: u8) -> Result<Self> {
        match b {
            0x01 => Ok(Command::Tcp),
            0x02 => Ok(Command::Udp),
            0x03 => Ok(Command::Mux),
            _ => Err(anyhow!("未知的命令类型: {}", b)),
        }
    }
}

#[derive(Debug)]
pub struct VlessRequest {
    pub version: u8,
    pub uuid: Uuid,
    pub command: Command,
    /// 目标地址
    pub address: Address,
    /// 附加数据长度
    pub addon_length: u8,
}

impl VlessRequest {
    /// 从字节流解码请求
    pub fn decode(buf: &mut BytesMut, allowed_uuids: &[Uuid]) -> Result<Self> {
        // 检查最小长度: version(1) + uuid(16) + addon_length(1) + command(1) + port(2) + addr_type(1)
        if buf.remaining() < 22 {
            return Err(anyhow!("缓冲区太小，无法解码 VLESS 请求"));
        }

        // 读取版本
        let version = buf.get_u8();
        if version != VLESS_VERSION {
            return Err(anyhow!("不支持的 VLESS 版本: {}", version));
        }

        // 读取 UUID (16 字节)
        let mut uuid_bytes = [0u8; 16];
        buf.copy_to_slice(&mut uuid_bytes);
        let uuid = Uuid::from_bytes(uuid_bytes);

        // 验证 UUID
        if !allowed_uuids.contains(&uuid) {
            return Err(anyhow!("未授权的 UUID: {}", uuid));
        }

        // 读取附加数据长度
        let addon_length = buf.get_u8();

        // 跳过附加数据
        if buf.remaining() < addon_length as usize {
            return Err(anyhow!("缓冲区太小，无法跳过附加数据"));
        }
        buf.advance(addon_length as usize);

        // 读取命令
        if buf.remaining() < 1 {
            return Err(anyhow!("缓冲区太小，无法读取命令"));
        }
        let command = Command::from_u8(buf.get_u8())?;

        // 读取目标地址
        let address = Address::decode(buf)?;

        Ok(VlessRequest {
            version,
            uuid,
            command,
            address,
            addon_length,
        })
    }
}
