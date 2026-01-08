use anyhow::{anyhow, Result};
use bytes::{Buf, BytesMut};
use std::io::Cursor;

/// TLS 内容类型
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum ContentType {
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
}

impl ContentType {
    pub fn from_u8(value: u8) -> Result<Self> {
        match value {
            20 => Ok(ContentType::ChangeCipherSpec),
            21 => Ok(ContentType::Alert),
            22 => Ok(ContentType::Handshake),
            23 => Ok(ContentType::ApplicationData),
            _ => Err(anyhow!("Unknown content type: {}", value)),
        }
    }
}

/// TLS 握手类型
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum HandshakeType {
    ClientHello = 1,
    ServerHello = 2,
    NewSessionTicket = 4,
    Certificate = 11,
    ServerKeyExchange = 12,
    CertificateRequest = 13,
    ServerHelloDone = 14,
    CertificateVerify = 15,
    ClientKeyExchange = 16,
    Finished = 20,
}

impl HandshakeType {
    pub fn from_u8(value: u8) -> Result<Self> {
        match value {
            1 => Ok(HandshakeType::ClientHello),
            2 => Ok(HandshakeType::ServerHello),
            4 => Ok(HandshakeType::NewSessionTicket),
            11 => Ok(HandshakeType::Certificate),
            12 => Ok(HandshakeType::ServerKeyExchange),
            13 => Ok(HandshakeType::CertificateRequest),
            14 => Ok(HandshakeType::ServerHelloDone),
            15 => Ok(HandshakeType::CertificateVerify),
            16 => Ok(HandshakeType::ClientKeyExchange),
            20 => Ok(HandshakeType::Finished),
            _ => Err(anyhow!("Unknown handshake type: {}", value)),
        }
    }
}

/// TLS 记录
#[derive(Debug, Clone)]
pub struct TlsRecord {
    pub content_type: ContentType,
    pub version: u16,
    pub payload: Vec<u8>,
}

impl TlsRecord {
    /// 从字节流解析 TLS 记录
    pub fn parse(buf: &mut BytesMut) -> Result<Option<Self>> {
        if buf.len() < 5 {
            return Ok(None); // 需要更多数据
        }

        let content_type = ContentType::from_u8(buf[0])?;
        let version = u16::from_be_bytes([buf[1], buf[2]]);
        let length = u16::from_be_bytes([buf[3], buf[4]]) as usize;

        if buf.len() < 5 + length {
            return Ok(None); // 需要更多数据
        }

        buf.advance(5);
        let payload = buf.split_to(length).to_vec();

        Ok(Some(TlsRecord {
            content_type,
            version,
            payload,
        }))
    }

    /// 将 TLS 记录编码为字节流
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(self.content_type as u8);
        buf.extend_from_slice(&self.version.to_be_bytes());
        buf.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }
}

/// ClientHello 消息
#[derive(Debug, Clone)]
pub struct ClientHello {
    pub version: u16,
    pub random: [u8; 32],
    pub session_id: Vec<u8>,
    pub cipher_suites: Vec<u16>,
    pub compression_methods: Vec<u8>,
    pub extensions: Vec<Extension>,
    pub raw_data: Vec<u8>, // 保存原始数据用于转发
}

impl ClientHello {
    /// 解析 ClientHello
    pub fn parse(data: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(data);

        // 检查握手类型
        let handshake_type = data[0];
        if handshake_type != HandshakeType::ClientHello as u8 {
            return Err(anyhow!("Not a ClientHello message"));
        }

        // 跳过握手类型和长度 (4 字节)
        cursor.set_position(4);

        // 读取版本
        let mut version_bytes = [0u8; 2];
        cursor.copy_to_slice(&mut version_bytes);
        let version = u16::from_be_bytes(version_bytes);

        // 读取 random (32 字节)
        let mut random = [0u8; 32];
        cursor.copy_to_slice(&mut random);

        // 读取 session_id
        let session_id_len = data[cursor.position() as usize];
        cursor.set_position(cursor.position() + 1);
        let mut session_id = vec![0u8; session_id_len as usize];
        cursor.copy_to_slice(&mut session_id);

        // 读取 cipher_suites
        let mut cipher_suites_len_bytes = [0u8; 2];
        cursor.copy_to_slice(&mut cipher_suites_len_bytes);
        let cipher_suites_len = u16::from_be_bytes(cipher_suites_len_bytes) as usize;
        let mut cipher_suites = Vec::new();
        for _ in 0..(cipher_suites_len / 2) {
            let mut suite_bytes = [0u8; 2];
            cursor.copy_to_slice(&mut suite_bytes);
            cipher_suites.push(u16::from_be_bytes(suite_bytes));
        }

        // 读取 compression_methods
        let compression_methods_len = data[cursor.position() as usize];
        cursor.set_position(cursor.position() + 1);
        let mut compression_methods = vec![0u8; compression_methods_len as usize];
        cursor.copy_to_slice(&mut compression_methods);

        // 读取 extensions
        let mut extensions = Vec::new();
        if cursor.position() < data.len() as u64 {
            let mut extensions_len_bytes = [0u8; 2];
            cursor.copy_to_slice(&mut extensions_len_bytes);
            let extensions_len = u16::from_be_bytes(extensions_len_bytes) as usize;
            let extensions_start = cursor.position() as usize;
            let extensions_data = &data[extensions_start..extensions_start + extensions_len];
            extensions = Extension::parse_all(extensions_data)?;
        }

        Ok(ClientHello {
            version,
            random,
            session_id,
            cipher_suites,
            compression_methods,
            extensions,
            raw_data: data.to_vec(),
        })
    }

    /// 获取 SNI (Server Name Indication)
    pub fn get_sni(&self) -> Option<String> {
        for ext in &self.extensions {
            if ext.extension_type == 0 {
                // SNI extension
                return Extension::parse_sni(&ext.data);
            }
        }
        None
    }

    /// 从 session_id 中提取 Reality short_id
    pub fn get_reality_short_id(&self) -> Option<Vec<u8>> {
        // Reality 使用 session_id 的前 8 字节作为 short_id
        if self.session_id.len() >= 8 {
            Some(self.session_id[..8].to_vec())
        } else {
            None
        }
    }

    /// 获取 ClientHello 的 random 字段
    pub fn get_random(&self) -> &[u8; 32] {
        &self.random
    }
}

/// TLS 扩展
#[derive(Debug, Clone)]
pub struct Extension {
    pub extension_type: u16,
    pub data: Vec<u8>,
}

impl Extension {
    /// 解析所有扩展
    pub fn parse_all(data: &[u8]) -> Result<Vec<Extension>> {
        let mut extensions = Vec::new();
        let mut cursor = Cursor::new(data);

        while cursor.position() < data.len() as u64 {
            let mut type_bytes = [0u8; 2];
            cursor.copy_to_slice(&mut type_bytes);
            let extension_type = u16::from_be_bytes(type_bytes);

            let mut len_bytes = [0u8; 2];
            cursor.copy_to_slice(&mut len_bytes);
            let length = u16::from_be_bytes(len_bytes) as usize;

            let mut ext_data = vec![0u8; length];
            cursor.copy_to_slice(&mut ext_data);

            extensions.push(Extension {
                extension_type,
                data: ext_data,
            });
        }

        Ok(extensions)
    }

    /// 解析 SNI 扩展
    pub fn parse_sni(data: &[u8]) -> Option<String> {
        if data.len() < 5 {
            return None;
        }

        // SNI 格式: [list_length(2)] [type(1)] [name_length(2)] [name]
        let name_length = u16::from_be_bytes([data[3], data[4]]) as usize;
        if data.len() < 5 + name_length {
            return None;
        }

        String::from_utf8(data[5..5 + name_length].to_vec()).ok()
    }
}

/// ServerHello 消息
#[derive(Debug, Clone)]
pub struct ServerHello {
    pub raw_data: Vec<u8>,
}

impl ServerHello {
    /// 从原始数据创建
    pub fn from_raw(data: Vec<u8>) -> Self {
        ServerHello { raw_data: data }
    }

    /// 修改 ServerHello 以注入 Reality 认证信息
    pub fn modify_for_reality(
        &mut self,
        private_key: &str,
        client_random: &[u8; 32],
    ) -> Result<()> {
        use super::auth::ServerHelloModifier;

        // 创建修改器
        let modifier = ServerHelloModifier::new(private_key)?;

        // 修改 raw_data 中的 random 字段
        modifier.modify_server_hello(&mut self.raw_data, client_random)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BufMut;

    #[test]
    fn test_tls_record_parse() {
        let mut buf = BytesMut::new();
        // TLS 记录: Handshake, TLS 1.2, length 5
        buf.put_u8(22); // Handshake
        buf.put_u16(0x0303); // TLS 1.2
        buf.put_u16(5); // Length
        buf.put_slice(&[1, 2, 3, 4, 5]); // Payload

        let record = TlsRecord::parse(&mut buf).unwrap().unwrap();
        assert_eq!(record.content_type, ContentType::Handshake);
        assert_eq!(record.version, 0x0303);
        assert_eq!(record.payload.len(), 5);
    }

    #[test]
    fn test_extension_parse_sni() {
        // SNI 扩展数据: [list_length(2)] [type(1)=0] [name_length(2)] [name]
        let mut data = Vec::new();
        data.extend_from_slice(&[0, 14]); // list length
        data.push(0); // type: hostname
        data.extend_from_slice(&[0, 11]); // name length
        data.extend_from_slice(b"example.com");

        let sni = Extension::parse_sni(&data).unwrap();
        assert_eq!(sni, "example.com");
    }
}
