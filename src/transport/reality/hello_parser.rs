use anyhow::{anyhow, Result};
use bytes::Buf;

pub struct ClientHelloInfo<'a> {
    pub session_id: &'a [u8],
    pub client_random: [u8; 32],
    pub public_key: Option<&'a [u8]>,
    pub server_name: Option<&'a str>,
}

/// 解析 ClientHello 消息，提取 SessionID, Random, X25519 Public Key 和 SNI
/// 注意：这是一个最小化实现，仅用于 Reality 预检
pub fn parse_client_hello(buf: &[u8]) -> Result<Option<ClientHelloInfo<'_>>> {
    // 检查是否是 TLS Handshake (0x16)
    if buf.len() < 5 || buf[0] != 0x16 {
        return Ok(None); // 不是 TLS 握手
    }

    // TLS Record Header: Type(1) + Ver(2) + Len(2)
    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if buf.len() < 5 + record_len {
        return Ok(None); // 数据包不完整
    }

    let handshake_payload = &buf[5..5 + record_len];
    if handshake_payload.len() < 4 {
        return Err(anyhow!("Short handshake payload"));
    }

    // Handshake Header: Type(1) + Len(3)
    let msg_type = handshake_payload[0];
    if msg_type != 0x01 {
        // 0x01 = ClientHello
        return Ok(None);
    }

    // Skip Handshake Header (4 bytes) and Version (2 bytes)
    if handshake_payload.len() < 38 {
        return Err(anyhow!("Short ClientHello"));
    }

    // Client Random (32 bytes)
    let mut client_random = [0u8; 32];
    client_random.copy_from_slice(&handshake_payload[6..38]);

    let mut cursor = &handshake_payload[38..];

    // Session ID
    if !cursor.has_remaining() {
        return Err(anyhow!("Short buffer for Session ID Len"));
    }
    let session_id_len = cursor.get_u8() as usize;
    if cursor.remaining() < session_id_len {
        return Err(anyhow!("Short buffer for Session ID"));
    }
    let session_id = &cursor[..session_id_len];
    cursor.advance(session_id_len);

    // Cipher Suites
    if cursor.remaining() < 2 {
        return Err(anyhow!("Short buffer for Cipher Suites Len"));
    }
    let cipher_suites_len = cursor.get_u16() as usize;
    if cursor.remaining() < cipher_suites_len {
        return Err(anyhow!("Short buffer for Cipher Suites"));
    }
    cursor.advance(cipher_suites_len);

    // Compression Methods
    if !cursor.has_remaining() {
        return Err(anyhow!("Short buffer for Compression Methods Len"));
    }
    let compression_methods_len = cursor.get_u8() as usize;
    if cursor.remaining() < compression_methods_len {
        return Err(anyhow!("Short buffer for Compression Methods"));
    }
    cursor.advance(compression_methods_len);

    // Extensions
    if cursor.remaining() < 2 {
        return Ok(Some(ClientHelloInfo {
            session_id,
            client_random,
            public_key: None,
            server_name: None,
        }));
    }

    let extensions_len = cursor.get_u16() as usize;
    if cursor.remaining() < extensions_len {
        return Err(anyhow!("Short buffer for Extensions"));
    }
    let mut extensions = &cursor[..extensions_len];

    let mut public_key = None;
    let mut server_name = None;

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

        if ext_type == 0x0000 {
            // Server Name Indication (SNI)
            if ext_data.remaining() >= 2 {
                let list_len = ext_data.get_u16() as usize;
                if ext_data.remaining() >= list_len {
                    let mut list = &ext_data[..list_len];
                    while list.has_remaining() {
                        if list.remaining() < 3 {
                            break;
                        }
                        let name_type = list.get_u8(); // 0x00 = HostName
                        let name_len = list.get_u16() as usize;
                        if list.remaining() < name_len {
                            break;
                        }

                        if name_type == 0x00 {
                            if let Ok(s) = std::str::from_utf8(&list[..name_len]) {
                                server_name = Some(s);
                            }
                            break;
                        }
                        list.advance(name_len);
                    }
                }
            }
        }

        // Key Share Extension (0x0033)
        if ext_type == 0x0033 {
            if ext_data.remaining() >= 2 {
                let shares_len = ext_data.get_u16() as usize;
                if ext_data.remaining() >= shares_len {
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
                            public_key = Some(&shares[..32]);
                            break;
                        } else {
                            shares.advance(key_len);
                        }
                    }
                }
            }
        }

        if public_key.is_some() && server_name.is_some() {
            break;
        }
    }

    Ok(Some(ClientHelloInfo {
        session_id,
        client_random,
        public_key,
        server_name,
    }))
}
