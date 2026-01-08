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
    /// 从字节流解析地址
    pub fn decode(buf: &mut BytesMut) -> Result<Self> {
        if buf.remaining() < 1 {
            return Err(anyhow!("缓冲区太小，无法读取地址类型"));
        }

        let addr_type = buf.get_u8();

        match addr_type {
            // IPv4
            0x01 => {
                if buf.remaining() < 6 {
                    return Err(anyhow!("缓冲区太小，无法读取 IPv4 地址"));
                }
                let mut octets = [0u8; 4];
                buf.copy_to_slice(&mut octets);
                let port = buf.get_u16();
                Ok(Address::Ipv4(Ipv4Addr::from(octets), port))
            }
            // 域名
            0x02 => {
                if buf.remaining() < 1 {
                    return Err(anyhow!("缓冲区太小，无法读取域名长度"));
                }
                let len = buf.get_u8() as usize;
                if buf.remaining() < len + 2 {
                    return Err(anyhow!("缓冲区太小，无法读取域名"));
                }
                let domain_bytes = buf.copy_to_bytes(len);
                let domain = String::from_utf8(domain_bytes.to_vec())?;
                let port = buf.get_u16();
                Ok(Address::Domain(domain, port))
            }
            // IPv6
            0x03 => {
                if buf.remaining() < 18 {
                    return Err(anyhow!("缓冲区太小，无法读取 IPv6 地址"));
                }
                let mut octets = [0u8; 16];
                buf.copy_to_slice(&mut octets);
                let port = buf.get_u16();
                Ok(Address::Ipv6(Ipv6Addr::from(octets), port))
            }
            _ => Err(anyhow!("未知的地址类型: {}", addr_type)),
        }
    }

    /// 将地址编码为字节流
    pub fn encode(&self, buf: &mut BytesMut) {
        match self {
            Address::Ipv4(ip, port) => {
                buf.put_u8(0x01);
                buf.put_slice(&ip.octets());
                buf.put_u16(*port);
            }
            Address::Domain(domain, port) => {
                buf.put_u8(0x02);
                buf.put_u8(domain.len() as u8);
                buf.put_slice(domain.as_bytes());
                buf.put_u16(*port);
            }
            Address::Ipv6(ip, port) => {
                buf.put_u8(0x03);
                buf.put_slice(&ip.octets());
                buf.put_u16(*port);
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
