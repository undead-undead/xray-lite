use anyhow::{anyhow, Result};
use bytes::{Buf, Bytes};

pub struct ClientHelloInfo {
    pub session_id: Vec<u8>,
    pub client_random: [u8; 32],
}

/// 解析 ClientHello 消息，提取 SessionID 和 Random
/// 注意：这是一个最小化实现，仅用于 Reality 预检
pub fn parse_client_hello(buf: &[u8]) -> Result<Option<ClientHelloInfo>> {
    // 检查是否是 TLS Handshake (0x16)
    if buf.len() < 5 || buf[0] != 0x16 {
        return Ok(None); // 不是 TLS 握手
    }

    // TLS Record Header: Type(1) + Ver(2) + Len(2)
    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if buf.len() < 5 + record_len {
        return Ok(None); // 数据包不完整
    }

    let mut cursor = &buf[5..]; // 跳过 Record Header

    // Handshake Header: Type(1) + Len(3)
    if cursor.remaining() < 4 {
        return Err(anyhow!("Short buffer"));
    }
    let msg_type = cursor.get_u8();
    if msg_type != 0x01 {
        // 0x01 = ClientHello
        return Ok(None);
    }

    // 跳过 Handshake Length (3 bytes)
    cursor.advance(3);

    // ClientHello Version (2 bytes)
    if cursor.remaining() < 2 {
        return Err(anyhow!("Short buffer for Version"));
    }
    cursor.advance(2);

    // Client Random (32 bytes)
    if cursor.remaining() < 32 {
        return Err(anyhow!("Short buffer for Random"));
    }
    let mut client_random = [0u8; 32];
    cursor.copy_to_slice(&mut client_random);

    // Session ID
    if cursor.remaining() < 1 {
        return Err(anyhow!("Short buffer for SessionID Len"));
    }
    let session_id_len = cursor.get_u8() as usize;
    if cursor.remaining() < session_id_len {
        return Err(anyhow!("Short buffer for SessionID"));
    }

    let mut session_id = vec![0u8; session_id_len];
    cursor.copy_to_slice(&mut session_id);

    Ok(Some(ClientHelloInfo {
        session_id,
        client_random,
    }))
}
