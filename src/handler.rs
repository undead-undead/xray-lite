use anyhow::Result;
use tracing::{info, error, debug};
use crate::server::AsyncStream;
use crate::protocol::vless::{VlessCodec, Command, VlessResponse};
use crate::network::ConnectionManager;

/// 处理 VLESS 会话核心逻辑
pub async fn serve_vless(
    mut stream: Box<dyn AsyncStream>,
    codec: VlessCodec,
    connection_manager: ConnectionManager,
    sniffing_enabled: bool,
    tcp_no_delay: bool,
) -> Result<()> {
    // 读取 VLESS 请求（带超时，支持多次读取）
    // Optimize: 增大缓冲区至 16KB 以减少系统调用，提升高吞吐场景性能
    let mut buf = bytes::BytesMut::with_capacity(16384);
    use tokio::io::AsyncReadExt;
    use tokio::time::{timeout, Duration};
    
    // 第一次读取，5秒超时
    let read_result = timeout(Duration::from_secs(30), stream.read_buf(&mut buf)).await;
    
    match read_result {
        Ok(Ok(0)) => {
            info!("客户端在发送VLESS请求前关闭了连接");
            return Ok(());
        },
        Ok(Ok(n)) => {
            debug!("📦 读取了 {} 字节的 VLESS 数据", n);
        },
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => {
            error!("读取 VLESS 请求超时");
            return Err(anyhow::anyhow!("Read timeout"));
        }
    }

    let request = match codec.decode_request(&mut buf) {
        Ok(req) => req,
        Err(e) => {
            // 检查是否是 HTTP 探测请求
            let buf_slice = &buf[..];
            let is_http_probe = buf_slice.windows(4).any(|w| 
                w == b"GET " || w == b"POST"
            ) || buf_slice.windows(4).any(|w| w == b"HEAD");
            
            if is_http_probe {
                let peek_len = buf.len().min(64);
                let peek = String::from_utf8_lossy(&buf[..peek_len]).replace("\r", "\\r").replace("\n", "\\n");
                info!("🔍 检测到 HTTP 探测请求 ({} bytes): \"{}\"", buf.len(), peek);
                use tokio::io::AsyncWriteExt;
                let _ = stream.write_all(b"HTTP/1.1 204 No Content\r\n\r\n").await;
                return Ok(());
            }
            
            let bytes_read = buf.len();
            let hex_dump = hex::encode(&buf[..bytes_read.min(128)]);
            error!("❌ VLESS 解码失败: {}. Bytes: {} Hex: {}", e, bytes_read, hex_dump);
            return Err(e);
        }
    };

    info!("📨 VLESS 请求: {:?} -> {}", request.command, request.address.to_string());

    // 发送 VLESS 响应
    let response = VlessResponse::new();
    let response_bytes = codec.encode_response(&response)?;
    
    use tokio::io::AsyncWriteExt;
    stream.write_all(&response_bytes).await?;
    stream.flush().await?; // 确保响应已发送

    // 根据命令类型处理
    match request.command {
        Command::Tcp | Command::Mux => {
            if request.command == Command::Mux {
                info!("⚠️ Experimental: Passing Mux traffic as TCP/Raw");
            }
            let mut target_address = request.address.to_string();
            let mut initial_data = Vec::new();

            // --- 🌟 SNIFFING START ---
            if !buf.is_empty() {
                initial_data.extend_from_slice(&buf);
                buf.clear(); 
            }

            if sniffing_enabled {
                // 如果没有初始数据，尝试再次通过超时读取
                if initial_data.is_empty() {
                    let mut temp_buf = vec![0u8; 16384];
                    if let Ok(Ok(n)) = timeout(Duration::from_millis(500), stream.read(&mut temp_buf)).await {
                         if n > 0 {
                             initial_data.extend_from_slice(&temp_buf[..n]);
                             debug!("Sniffing: 读取了额外的 {} 字节", n);
                         }
                    }
                }

                if !initial_data.is_empty() {
                    if let Some(sni) = crate::protocol::sniffer::sniff_tls_sni(&initial_data) {
                        info!("👃 Sniffed SNI: {} (Override: {})", sni, target_address);
                        // 判断是否需要覆盖目标地址
                        // 这里不再做 dest_override 过滤，简单起见总是覆盖
                        // 实际应根据配置判断
                         target_address = format!("{}:443", sni);
                    }
                }
            }
            // --- SNIFFING END ---

            info!("🔗 连接目标: {}", target_address);
            
            // 连接远程服务器
            let mut remote_stream = match tokio::net::TcpStream::connect(&target_address).await {
                Ok(s) => s,
                Err(e) => {
                    error!("无法连接到目标 {}: {}", target_address, e);
                    return Err(e.into());
                }
            };
            
            // TCP No Delay
            if tcp_no_delay {
                if let Err(e) = remote_stream.set_nodelay(true) {
                    error!("Remote: 设置 TCP_NODELAY 失败: {}", e);
                }
            }

            // 发送初始数据
            if !initial_data.is_empty() {
                remote_stream.write_all(&initial_data).await?;
            }

            // 开始双向转发
            connection_manager
                .handle_connection(stream, remote_stream)
                .await?;
        }
        Command::Udp => {
            info!("📡 UDP 请求: {}", request.address.to_string());
            
            // 使用 Tokio 绑定 UDP socket (不强制 buffer 大小，让系统自动管理)
            let udp_socket = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
                Ok(s) => s,
                Err(e) => {
                    error!("无法绑定 UDP socket: {}", e);
                    return Err(e.into());
                }
            };
            
            // 解析目标地址
            let target_addr = request.address.to_string();
            let initial_target: std::net::SocketAddr = match tokio::net::lookup_host(&target_addr).await {
                Ok(mut addrs) => {
                    if let Some(addr) = addrs.next() {
                        info!("🔗 UDP 初始目标: {}", addr);
                        addr
                    } else {
                        error!("无法解析 UDP 目标地址: {}", target_addr);
                        return Err(anyhow::anyhow!("DNS resolution failed"));
                    }
                }
                Err(e) => {
                    error!("DNS 解析失败: {}", e);
                    return Err(e.into());
                }
            };
            
            // UDP 会话超时 (5分钟)
            let session_timeout = Duration::from_secs(300);
            
            let udp_socket = std::sync::Arc::new(udp_socket);
            let udp_socket_recv = udp_socket.clone();
            
            // 发送初始 UDP 数据
            if !buf.is_empty() {
               if buf.len() >= 2 {
                    let len = ((buf[0] as usize) << 8) | (buf[1] as usize);
                    if buf.len() >= 2 + len {
                        let payload = &buf[2..2+len];
                        if let Err(e) = udp_socket.send_to(payload, initial_target).await {
                            error!("UDP 发送失败: {}", e);
                        } else {
                            debug!("UDP 发送了 {} 字节 (初始数据)", len);
                        }
                    }
                }
            }
            
            let (mut stream_read, mut stream_write) = tokio::io::split(stream);
            let initial_target_clone = initial_target;
            
            // 客户端 -> UDP
            let send_task = async {
                let mut read_buf = vec![0u8; 16384]; // 优化：16KB Buffer
                let mut last_activity = tokio::time::Instant::now();
                
                loop {
                    let read_timeout = session_timeout.saturating_sub(last_activity.elapsed());
                    let mut len_buf = [0u8; 2];
                    match timeout(read_timeout, stream_read.read_exact(&mut len_buf)).await {
                        Ok(Ok(_)) => {
                            last_activity = tokio::time::Instant::now();
                            let len = ((len_buf[0] as usize) << 8) | (len_buf[1] as usize);
                            if len == 0 || len > read_buf.len() {
                                break;
                            }
                            match stream_read.read_exact(&mut read_buf[..len]).await {
                                Ok(_) => {
                                    if let Err(_) = udp_socket.send_to(&read_buf[..len], initial_target_clone).await {
                                        break;
                                    }
                                }
                                Err(_) => break,
                            }
                        }
                        Ok(Err(_)) | Err(_) => break,
                    }
                }
            };
            
            // UDP -> 客户端
            let recv_task = async {
                let mut recv_buf = vec![0u8; 16384]; // 优化：16KB Buffer
                let mut last_activity = tokio::time::Instant::now();
                loop {
                    let recv_timeout = session_timeout.saturating_sub(last_activity.elapsed());
                    match timeout(recv_timeout, udp_socket_recv.recv_from(&mut recv_buf)).await {
                        Ok(Ok((n, _))) => {
                            if n == 0 { break; }
                            last_activity = tokio::time::Instant::now();
                            let len_bytes = [(n >> 8) as u8, (n & 0xff) as u8];
                            let mut frame = Vec::with_capacity(2 + n);
                            frame.extend_from_slice(&len_bytes);
                            frame.extend_from_slice(&recv_buf[..n]);
                            if stream_write.write_all(&frame).await.is_err() { break; }
                            if stream_write.flush().await.is_err() { break; }
                        }
                        Ok(Err(_)) | Err(_) => break,
                    }
                }
            };
            
            tokio::select! {
                _ = send_task => {}
                _ = recv_task => {}
            }
            info!("📡 UDP 会话结束");
        }

    }

    Ok(())
}
