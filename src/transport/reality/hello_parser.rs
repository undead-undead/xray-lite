use anyhow::{anyhow, Result};
use bytes::{Buf, Bytes};

pub struct ClientHelloInfo {
    pub session_id: Vec<u8>,
    pub client_random: [u8; 32],
    pub public_key: Option<Vec<u8>>,
}

/// 解析 ClientHello 消息，提取 SessionID, Random 和 X25519 Public Key
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

    // Cipher Suites
    if cursor.remaining() < 2 {
        return Err(anyhow!("Short buffer for CipherSuites Len"));
    }
    let cipher_suites_len = cursor.get_u16() as usize;
    if cursor.remaining() < cipher_suites_len {
        return Err(anyhow!("Short buffer for CipherSuites"));
    }
    cursor.advance(cipher_suites_len);

    // Compression Methods
    if cursor.remaining() < 1 {
        return Err(anyhow!("Short buffer for CompressionMethods Len"));
    }
    let compression_methods_len = cursor.get_u8() as usize;
    if cursor.remaining() < compression_methods_len {
        return Err(anyhow!("Short buffer for CompressionMethods"));
    }
    cursor.advance(compression_methods_len);

    // Extensions
    if cursor.remaining() < 2 {
        // No extensions?
        return Ok(Some(ClientHelloInfo {
            session_id,
            client_random,
            public_key: None,
        }));
    }

    let extensions_len = cursor.get_u16() as usize;
    if cursor.remaining() < extensions_len {
        return Err(anyhow!("Short buffer for Extensions"));
    }
    let mut extensions = &cursor[..extensions_len];

    let mut public_key = None;

    while extensions.has_remaining() {
        if extensions.remaining() < 4 {
            break;
        }
        let ext_type = extensions.get_u16();
        let ext_len = extensions.get_u16() as usize;

        if extensions.remaining() < ext_len {
            break;
        }
        let mut ext_data = &extensions[..ext_len];
        extensions.advance(ext_len);

        // Key Share Extension (0x0033)
        if ext_type == 0x0033 {
            // KeyShareClientHello format:
            // client_shares_len (2 bytes)
            // ClientShareEntry...

            if ext_data.remaining() < 2 {
                continue;
            }
            let shares_len = ext_data.get_u16() as usize;
            if ext_data.remaining() < shares_len {
                continue;
            }

            let mut shares = &ext_data[..shares_len];
            while shares.has_remaining() {
                if shares.remaining() < 4 {
                    break;
                }
                let group = shares.get_u16();
                let key_len = shares.get_u16() as usize;

                if shares.remaining() < key_len {
                    break;
                }

                // Group X25519 is 0x001d
                if group == 0x001d && key_len == 32 {
                    let mut key = vec![0u8; 32];
                    shares.copy_to_slice(&mut key);
                    public_key = Some(key);
                    break; // Found it
                } else {
                    shares.advance(key_len);
                }
            }
        }

        if public_key.is_some() {
            break;
        }
    }

    Ok(Some(ClientHelloInfo {
        session_id,
        client_random,
        public_key,
    }))
}
