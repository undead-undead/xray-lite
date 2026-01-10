//! Proxy Protocol v1/v2 解析器
//!
//! 支持从 HAProxy 或其他负载均衡器获取真实客户端 IP

use anyhow::{anyhow, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Proxy Protocol 头部信息
#[derive(Debug, Clone)]
pub struct ProxyHeader {
    /// 真实客户端地址
    pub source_addr: SocketAddr,
    /// 目标地址
    pub dest_addr: SocketAddr,
}

/// Proxy Protocol v1 签名
const PROXY_V1_SIGNATURE: &[u8] = b"PROXY ";

/// Proxy Protocol v2 签名
const PROXY_V2_SIGNATURE: &[u8] = &[
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

/// 解析 Proxy Protocol 头部
///
/// 返回 (ProxyHeader, 剩余数据) 或错误
pub fn parse_proxy_protocol(data: &[u8]) -> Result<(ProxyHeader, usize)> {
    // 检查 v1 签名
    if data.starts_with(PROXY_V1_SIGNATURE) {
        return parse_v1(data);
    }

    // 检查 v2 签名
    if data.len() >= 12 && data[..12] == *PROXY_V2_SIGNATURE {
        return parse_v2(data);
    }

    Err(anyhow!("无效的 Proxy Protocol 头部"))
}

/// 解析 Proxy Protocol v1
/// 格式: PROXY TCP4 192.168.1.1 10.0.0.1 56789 443\r\n
fn parse_v1(data: &[u8]) -> Result<(ProxyHeader, usize)> {
    // 查找 \r\n
    let end = data
        .iter()
        .position(|&b| b == b'\r')
        .ok_or_else(|| anyhow!("未找到 CRLF"))?;

    if data.len() < end + 2 || data[end + 1] != b'\n' {
        return Err(anyhow!("无效的行结束符"));
    }

    let line = std::str::from_utf8(&data[..end])?;
    let parts: Vec<&str> = line.split(' ').collect();

    if parts.len() < 6 {
        return Err(anyhow!("Proxy Protocol v1 格式错误"));
    }

    let protocol = parts[1];
    let src_ip = parts[2];
    let dst_ip = parts[3];
    let src_port: u16 = parts[4].parse()?;
    let dst_port: u16 = parts[5].parse()?;

    let (src_addr, dst_addr) = match protocol {
        "TCP4" | "UDP4" => {
            let src: Ipv4Addr = src_ip.parse()?;
            let dst: Ipv4Addr = dst_ip.parse()?;
            (
                SocketAddr::new(IpAddr::V4(src), src_port),
                SocketAddr::new(IpAddr::V4(dst), dst_port),
            )
        }
        "TCP6" | "UDP6" => {
            let src: Ipv6Addr = src_ip.parse()?;
            let dst: Ipv6Addr = dst_ip.parse()?;
            (
                SocketAddr::new(IpAddr::V6(src), src_port),
                SocketAddr::new(IpAddr::V6(dst), dst_port),
            )
        }
        "UNKNOWN" => {
            // UNKNOWN 协议，使用占位符
            (
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            )
        }
        _ => return Err(anyhow!("未知协议: {}", protocol)),
    };

    Ok((
        ProxyHeader {
            source_addr: src_addr,
            dest_addr: dst_addr,
        },
        end + 2, // 消费的字节数 (包括 \r\n)
    ))
}

/// 解析 Proxy Protocol v2
fn parse_v2(data: &[u8]) -> Result<(ProxyHeader, usize)> {
    if data.len() < 16 {
        return Err(anyhow!("Proxy Protocol v2 头部太短"));
    }

    // 检查版本和命令
    let ver_cmd = data[12];
    let _version = (ver_cmd >> 4) & 0x0F;
    let _command = ver_cmd & 0x0F;

    // 地址族和协议
    let fam_prot = data[13];
    let family = (fam_prot >> 4) & 0x0F;
    let _protocol = fam_prot & 0x0F;

    // 地址长度
    let addr_len = ((data[14] as usize) << 8) | (data[15] as usize);

    if data.len() < 16 + addr_len {
        return Err(anyhow!("数据不完整"));
    }

    let (src_addr, dst_addr) = match family {
        0x1 => {
            // IPv4
            if addr_len < 12 {
                return Err(anyhow!("IPv4 地址长度错误"));
            }
            let src = Ipv4Addr::new(data[16], data[17], data[18], data[19]);
            let dst = Ipv4Addr::new(data[20], data[21], data[22], data[23]);
            let src_port = ((data[24] as u16) << 8) | (data[25] as u16);
            let dst_port = ((data[26] as u16) << 8) | (data[27] as u16);
            (
                SocketAddr::new(IpAddr::V4(src), src_port),
                SocketAddr::new(IpAddr::V4(dst), dst_port),
            )
        }
        0x2 => {
            // IPv6
            if addr_len < 36 {
                return Err(anyhow!("IPv6 地址长度错误"));
            }
            let src_bytes: [u8; 16] = data[16..32].try_into()?;
            let dst_bytes: [u8; 16] = data[32..48].try_into()?;
            let src = Ipv6Addr::from(src_bytes);
            let dst = Ipv6Addr::from(dst_bytes);
            let src_port = ((data[48] as u16) << 8) | (data[49] as u16);
            let dst_port = ((data[50] as u16) << 8) | (data[51] as u16);
            (
                SocketAddr::new(IpAddr::V6(src), src_port),
                SocketAddr::new(IpAddr::V6(dst), dst_port),
            )
        }
        _ => {
            // 未知或本地
            (
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            )
        }
    };

    Ok((
        ProxyHeader {
            source_addr: src_addr,
            dest_addr: dst_addr,
        },
        16 + addr_len,
    ))
}

/// 检查数据是否以 Proxy Protocol 头部开始
pub fn is_proxy_protocol(data: &[u8]) -> bool {
    data.starts_with(PROXY_V1_SIGNATURE) || (data.len() >= 12 && data[..12] == *PROXY_V2_SIGNATURE)
}
