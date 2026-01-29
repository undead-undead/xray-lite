use anyhow::{anyhow, Result};
use bytes::{Buf, BufMut, BytesMut};
use std::net::{Ipv4Addr, Ipv6Addr};

/// VLESS 地址类型
#[derive(Debug, Clone, PartialEq)]
pub enum Address {
    /// IPv4 地址
    Ipv4(Ipv4Addr, u16),
    /// IPv6 地址
    Ipv6(Ipv6Addr, u16),
    /// 域名
    Domain(String, u16),
}

impl Address {
    /// 从字节流解析地址 (支持流式解码)
    /// 返回:
    /// - Ok(Some(addr)): 解析成功
    /// - Ok(None): 数据不足，需要更多数据
    /// - Err(e): 数据格式错误
    pub fn decode(buf: &mut BytesMut) -> Result<Option<Self>> {
        // 1. Check minimal length (Port 2 + Type 1 = 3 bytes)
        if buf.remaining() < 3 {
            return Ok(None);
        }

        // Peek type to determine needed length
        // Port (0..2), Type (2)
        let addr_type = buf[2];

        // 2. Check complete length based on type
        match addr_type {
            // IPv4: Port(2) + Type(1) + IP(4) = 7 bytes
            0x01 => {
                if buf.remaining() < 7 {
                    return Ok(None);
                }
                buf.advance(2); // Skip port (read later)
                buf.advance(1); // Skip type
                let mut octets = [0u8; 4];
                buf.copy_to_slice(&mut octets);
                // Rewind to read port correctly (or just read port first above)
                // Let's rewrite to follow read flow but use peek/check first
            }
            // ... logic is cleaner if we just check length first using peek
            _ => {}
        }

        // Re-implementing with cleaner flow:
        // We need to verify we have enough bytes BEFORE reading anything to avoid partial consumption.

        let port = u16::from_be_bytes([buf[0], buf[1]]);
        let addr_type = buf[2];

        match addr_type {
            // IPv4
            0x01 => {
                if buf.remaining() < 7 {
                    return Ok(None);
                }
                buf.advance(3); // Port + Type
                let mut octets = [0u8; 4];
                buf.copy_to_slice(&mut octets);
                Ok(Some(Address::Ipv4(Ipv4Addr::from(octets), port)))
            }
            // Domain
            0x02 => {
                if buf.remaining() < 4 {
                    return Ok(None);
                } // Port+Type+Len
                let len = buf[3] as usize;
                if buf.remaining() < 4 + len {
                    return Ok(None);
                }

                buf.advance(4); // Port + Type + Len
                let domain_bytes = buf.copy_to_bytes(len);
                let domain = String::from_utf8(domain_bytes.to_vec())?;
                Ok(Some(Address::Domain(domain, port)))
            }
            // IPv6
            0x03 => {
                if buf.remaining() < 19 {
                    return Ok(None);
                } // 3 + 16
                buf.advance(3);
                let mut octets = [0u8; 16];
                buf.copy_to_slice(&mut octets);
                Ok(Some(Address::Ipv6(Ipv6Addr::from(octets), port)))
            }
            // Mux 0x00 ?? (Rarely used in VLESS standard but supported in some cores)
            // Let's keep it assuming your implementation needs it, but handle partial
            // Mux 0x00 ?? (Rarely used in VLESS standard but supported in some cores)
            // Let's keep it assuming your implementation needs it, but handle partial
            0x00 => {
                // Format: Port(2) + Type(1) + Session(1) = 4 bytes minimum
                // Followed by actual address
                if buf.remaining() < 4 {
                    return Ok(None);
                }

                // We don't need to read SessionID for address decoding, but we need to know where nested addr starts.
                // Nested address starts at index 4 (0,1=Port, 2=Type, 3=SessionID)

                // Make a view of the remaining buffer starting from the nested address
                // We rely on the fact that decode() uses indexing and doesn't consume if incomplete
                let mut nested_buf = BytesMut::from(&buf[4..]);

                // Recursively check if the nested address is complete.
                // Note: 'nested_buf' is a COPY of the data (shallow cow copy), so modifying it in decode
                // won't affect 'buf'. Wait, BytesMut::from(&[u8]) copies data!
                // This is slightly inefficient (mem copy) but safe and correct for logic check.
                // Given Mux headers are small, it's acceptable.

                match Self::decode(&mut nested_buf)? {
                    Some(real_addr) => {
                        // Nested address is complete.
                        // Calculate consumed length:
                        // Original nested_buf length - remaining length after decode
                        let original_nested_len = buf.len() - 4;
                        let consumed_nested = original_nested_len - nested_buf.len();

                        // Advance main buffer: 4 (Header) + consumed_nested
                        buf.advance(4 + consumed_nested);

                        Ok(Some(real_addr))
                    }
                    None => Ok(None), // Nested data incomplete
                }
            }
            _ => Err(anyhow!("未知的地址类型: {}", addr_type)),
        }
    }

    /// 将地址编码为字节流
    /// 注意：VLESS 协议使用 PortThenAddress 格式
    pub fn encode(&self, buf: &mut BytesMut) {
        match self {
            Address::Ipv4(ip, port) => {
                buf.put_u16(*port); // 先写 Port
                buf.put_u8(0x01); // 再写 Address Type
                buf.put_slice(&ip.octets());
            }
            Address::Domain(domain, port) => {
                buf.put_u16(*port); // 先写 Port
                buf.put_u8(0x02); // 再写 Address Type
                buf.put_u8(domain.len() as u8);
                buf.put_slice(domain.as_bytes());
            }
            Address::Ipv6(ip, port) => {
                buf.put_u16(*port); // 先写 Port
                buf.put_u8(0x03); // 再写 Address Type
                buf.put_slice(&ip.octets());
            }
        }
    }

    /// 获取端口
    pub fn port(&self) -> u16 {
        match self {
            Address::Ipv4(_, port) | Address::Ipv6(_, port) | Address::Domain(_, port) => *port,
        }
    }

    /// 转换为字符串表示
    pub fn to_string(&self) -> String {
        match self {
            Address::Ipv4(ip, port) => format!("{}:{}", ip, port),
            Address::Ipv6(ip, port) => format!("[{}]:{}", ip, port),
            Address::Domain(domain, port) => format!("{}:{}", domain, port),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_encode_decode() {
        let addr = Address::Ipv4(Ipv4Addr::new(192, 168, 1, 1), 443);
        let mut buf = BytesMut::new();
        addr.encode(&mut buf);

        let decoded = Address::decode(&mut buf).unwrap();
        assert_eq!(addr, decoded);
    }

    #[test]
    fn test_domain_encode_decode() {
        let addr = Address::Domain("example.com".to_string(), 443);
        let mut buf = BytesMut::new();
        addr.encode(&mut buf);

        let decoded = Address::decode(&mut buf).unwrap();
        assert_eq!(addr, decoded);
    }

    #[test]
    fn test_ipv6_encode_decode() {
        let addr = Address::Ipv6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 443);
        let mut buf = BytesMut::new();
        addr.encode(&mut buf);

        let decoded = Address::decode(&mut buf).unwrap();
        assert_eq!(addr, decoded);
    }
}
