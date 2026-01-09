use anyhow::Result;
use bytes::Buf;
use std::io::Cursor;

/// 尝试从数据包中嗅探 TLS SNI (Server Name Indication)
pub fn sniff_tls_sni(data: &[u8]) -> Option<String> {
    // 最小 TLS ClientHello 长度检查
    if data.len() < 40 {
        return None;
    }

    let mut cursor = Cursor::new(data);

    // 1. Record Layer
    let content_type = cursor.get_u8();
    if content_type != 0x16 {
        // Update: Handshake
        return None;
    }

    // Version (e.g., 0x0301, 0x0303)
    let _version = cursor.get_u16();
    let length = cursor.get_u16() as usize;

    if cursor.remaining() < length {
        return None; // 数据包不完整，无法嗅探
    }

    // 2. Handshake Layer
    let handshake_type = cursor.get_u8();
    if handshake_type != 0x01 {
        // ClientHello
        return None;
    }

    // Length (3 bytes)
    cursor.advance(3);

    // Version (2 bytes)
    cursor.advance(2);

    // Random (32 bytes)
    if cursor.remaining() < 32 {
        return None;
    }
    cursor.advance(32);

    // Session ID
    if cursor.remaining() < 1 {
        return None;
    }
    let session_id_len = cursor.get_u8() as usize;
    if cursor.remaining() < session_id_len {
        return None;
    }
    cursor.advance(session_id_len);

    // Cipher Suites
    if cursor.remaining() < 2 {
        return None;
    }
    let cipher_suites_len = cursor.get_u16() as usize;
    if cursor.remaining() < cipher_suites_len {
        return None;
    }
    cursor.advance(cipher_suites_len);

    // Compression Methods
    if cursor.remaining() < 1 {
        return None;
    }
    let comp_methods_len = cursor.get_u8() as usize;
    if cursor.remaining() < comp_methods_len {
        return None;
    }
    cursor.advance(comp_methods_len);

    // Extensions
    if cursor.remaining() < 2 {
        return None;
    }
    let extensions_len = cursor.get_u16() as usize;
    if cursor.remaining() < extensions_len {
        return None;
    }

    // 遍历扩展
    let mut ext_cursor = Cursor::new(&data[cursor.position() as usize..]);
    while ext_cursor.remaining() >= 4 {
        let ext_type = ext_cursor.get_u16();
        let ext_len = ext_cursor.get_u16() as usize;

        if ext_cursor.remaining() < ext_len {
            break;
        }

        // Extension: Server Name (0x0000)
        if ext_type == 0x0000 {
            if ext_len < 2 {
                return None;
            }
            // SNI List Length
            let list_len = ext_cursor.get_u16() as usize;
            if ext_cursor.remaining() < list_len {
                return None;
            }

            let mut list_cursor =
                Cursor::new(&ext_cursor.get_ref()[ext_cursor.position() as usize..]);

            // 遍历 ServerNameList
            while list_cursor.remaining() >= 3 {
                let name_type = list_cursor.get_u8();
                let name_len = list_cursor.get_u16() as usize;

                if list_cursor.remaining() < name_len {
                    break;
                }

                // NameType: HostName (0x00)
                if name_type == 0x00 {
                    let name_bytes = &list_cursor.get_ref()[list_cursor.position() as usize
                        ..list_cursor.position() as usize + name_len];
                    if let Ok(name) = String::from_utf8(name_bytes.to_vec()) {
                        return Some(name);
                    }
                }
                list_cursor.advance(name_len);
            }
        }

        ext_cursor.advance(ext_len);
    }

    None
}
