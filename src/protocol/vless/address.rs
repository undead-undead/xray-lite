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
    /// 检查地址编码长度（不消耗 buffer）
    /// 返回: Ok(Some(len)) 表示完整长度, Ok(None) 表示数据不足, Err 表示类型错误
    pub fn check_len(buf: &[u8]) -> Result<Option<usize>> {
        if buf.len() < 3 {
            return Ok(None);
        }

        // buf[0], buf[1] are Port
        let addr_type = buf[2];
        let base_len = 3;

        match addr_type {
            // IPv4: 3 + 4 = 7
            0x01 => {
                if buf.len() < 7 {
                    Ok(None)
                } else {
                    Ok(Some(7))
                }
            }
            // Domain: 3 + 1 + len
            0x02 => {
                if buf.len() < 4 {
                    return Ok(None);
                }
                let len = buf[3] as usize;
                let total = 4 + len;
                if buf.len() < total {
                    Ok(None)
                } else {
                    Ok(Some(total))
                }
            }
            // IPv6: 3 + 16 = 19
            0x03 => {
                if buf.len() < 19 {
                    Ok(None)
                } else {
                    Ok(Some(19))
                }
            }
            // Unknown
            _ => Err(anyhow!("未知的地址类型: {}", addr_type)),
        }
    }

    /// 从字节流解析地址
    pub fn decode(buf: &mut BytesMut) -> Result<Self> {
        if buf.remaining() < 3 {
            return Err(anyhow!("缓冲区太小，无法读取地址头"));
        }

        let port = u16::from_be_bytes([buf[0], buf[1]]);
        let addr_type = buf[2];
        buf.advance(3);

        match addr_type {
            // IPv4
            0x01 => {
                if buf.remaining() < 4 {
                    return Err(anyhow!("缓冲区太小，无法读取 IPv4 地址"));
                }
                let mut octets = [0u8; 4];
                buf.copy_to_slice(&mut octets);
                Ok(Address::Ipv4(Ipv4Addr::from(octets), port))
            }
            // Domain
            0x02 => {
                if buf.remaining() < 1 {
                    return Err(anyhow!("缓冲区太小，无法读取域名长度"));
                }
                let len = buf.get_u8() as usize;

                if buf.remaining() < len {
                    return Err(anyhow!("缓冲区太小，无法读取域名"));
                }
                let domain_bytes = buf.copy_to_bytes(len);
                let domain = String::from_utf8(domain_bytes.to_vec())?;
                Ok(Address::Domain(domain, port))
            }
            // IPv6
            0x03 => {
                if buf.remaining() < 16 {
                    return Err(anyhow!("缓冲区太小，无法读取 IPv6 地址"));
                }
                let mut octets = [0u8; 16];
                buf.copy_to_slice(&mut octets);
                Ok(Address::Ipv6(Ipv6Addr::from(octets), port))
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
