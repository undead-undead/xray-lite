/// 尝试从数据包中嗅探 TLS SNI (Server Name Indication)
/// 这是一个纯 Rust 实现，不通过 bytes crate，以避免依赖问题
pub fn sniff_tls_sni(data: &[u8]) -> Option<String> {
    let mut pos = 0;
    if data.len() < 40 {
        return None;
    }

    // 1. Record Layer
    // ContentType(1) must be Handshake (0x16)
    if data[pos] != 0x16 {
        return None;
    }
    pos += 1;

    // Version (2) + Length (2)
    pos += 4;

    // 2. Handshake Layer
    if pos >= data.len() {
        return None;
    }
    // HandshakeType(1) must be ClientHello (0x01)
    if data[pos] != 0x01 {
        return None;
    }
    pos += 1;

    // Length(3) + Version(2) + Random(32)
    pos += 3 + 2 + 32;
    if pos >= data.len() {
        return None;
    }

    // SessionID
    let sess_id_len = data[pos] as usize;
    pos += 1 + sess_id_len;
    if pos >= data.len() {
        return None;
    }

    // Cipher Suites
    if pos + 2 > data.len() {
        return None;
    }
    let cipher_len = ((data[pos] as usize) << 8) | (data[pos + 1] as usize);
    pos += 2 + cipher_len;
    if pos >= data.len() {
        return None;
    }

    // Compression Methods
    if pos + 1 > data.len() {
        return None;
    }
    let comp_len = data[pos] as usize;
    pos += 1 + comp_len;
    if pos >= data.len() {
        return None;
    }

    // Extensions
    if pos + 2 > data.len() {
        return None;
    }
    let ext_len = ((data[pos] as usize) << 8) | (data[pos + 1] as usize);
    pos += 2;

    let end_ext = pos + ext_len;
    if end_ext > data.len() {
        return None;
    }

    while pos + 4 <= end_ext {
        let ext_type = ((data[pos] as usize) << 8) | (data[pos + 1] as usize);
        let len = ((data[pos + 2] as usize) << 8) | (data[pos + 3] as usize);
        pos += 4;

        if pos + len > end_ext {
            break;
        }

        if ext_type == 0x0000 {
            // ServerName Extension
            // ServerNameList Length (2)
            if len < 2 {
                return None;
            }
            let list_len = ((data[pos] as usize) << 8) | (data[pos + 1] as usize);
            let end_list = pos + 2 + list_len;
            let mut p2 = pos + 2;

            while p2 + 3 <= end_list {
                let name_type = data[p2];
                let name_len = ((data[p2 + 1] as usize) << 8) | (data[p2 + 2] as usize);
                p2 += 3;

                if p2 + name_len > end_list {
                    break;
                }

                if name_type == 0x00 {
                    // HostName
                    return String::from_utf8(data[p2..p2 + name_len].to_vec()).ok();
                }
                p2 += name_len;
            }
        }

        pos += len;
    }

    None
}
