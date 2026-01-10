use anyhow::Result;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{error, info, warn, debug};
use uuid::Uuid;

use crate::config::{Config, Inbound, Security};
use crate::network::ConnectionManager;
use crate::protocol::vless::{Command, VlessCodec};
use crate::transport::{RealityServer, XhttpServer};

/// 定义通用的 AsyncStream trait 以支持 TCP 和 TLS 流
pub trait AsyncStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> AsyncStream for T {}

/// 代理服务器
pub struct Server {
    config: Config,
    connection_manager: ConnectionManager,
}

impl Server {
    /// 创建新的服务器
    pub fn new(config: Config) -> Result<Self> {
        Ok(Self {
            config,
            connection_manager: ConnectionManager::new(),
        })
    }

    /// 运行服务器
    pub async fn run(self) -> Result<()> {
        let mut handles = vec![];

        // 为每个入站配置启动监听器
        for inbound in self.config.inbounds.clone() {
            let connection_manager = self.connection_manager.clone();
            
            let handle = tokio::spawn(async move {
                if let Err(e) = Self::run_inbound(inbound, connection_manager).await {
                    error!("入站处理失败: {}", e);
                }
            });

            handles.push(handle);
        }

        // 等待所有任务完成
        for handle in handles {
            handle.await?;
        }

        Ok(())
    }

    /// 运行单个入站配置
    async fn run_inbound(inbound: Inbound, connection_manager: ConnectionManager) -> Result<()> {
        let addr = format!("{}:{}", inbound.listen, inbound.port);
        let sockopt = &inbound.stream_settings.sockopt;
        
        // 使用 socket2 创建监听器以支持 TCP Fast Open
        let listener = if sockopt.tcp_fast_open {
            use socket2::{Socket, Domain, Type, Protocol};
            use std::net::SocketAddr;
            
            let socket_addr: SocketAddr = addr.parse()?;
            let domain = if socket_addr.is_ipv4() {
                Domain::IPV4
            } else {
                Domain::IPV6
            };
            
            let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
            
            // 设置 SO_REUSEADDR
            socket.set_reuse_address(true)?;
            
            // 启用 TCP Fast Open (队列长度为 256)
            #[cfg(target_os = "linux")]
            {
                // Linux 特有的 TCP_FASTOPEN 选项
                use std::os::unix::io::AsRawFd;
                let fd = socket.as_raw_fd();
                let val: libc::c_int = 256;
                unsafe {
                    libc::setsockopt(
                        fd,
                        libc::IPPROTO_TCP,
                        libc::TCP_FASTOPEN,
                        &val as *const _ as *const libc::c_void,
                        std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                    );
                }
                info!("🚀 TCP Fast Open 已启用 (队列长度: 256)");
            }
            
            socket.bind(&socket_addr.into())?;
            socket.listen(1024)?;
            socket.set_nonblocking(true)?;
            
            TcpListener::from_std(std::net::TcpListener::from(socket))?
        } else {
            TcpListener::bind(&addr).await?
        };

        info!("🎯 监听 {} (协议: {:?})", addr, inbound.protocol);

        // 创建 VLESS 编解码器
        let uuids: Vec<Uuid> = inbound
            .settings
            .clients
            .iter()
            .filter_map(|c| Uuid::parse_str(&c.id).ok())
            .collect();

        let codec = VlessCodec::new(uuids);

        // 创建 Reality 服务器 (如果启用)
        let reality_server = if matches!(inbound.stream_settings.security, Security::Reality) {
            if let Some(reality_settings) = &inbound.stream_settings.reality_settings {
                let reality_config = crate::transport::reality::RealityConfig {
                    dest: reality_settings.dest.clone(),
                    server_names: reality_settings.server_names.clone(),
                    private_key: reality_settings.private_key.clone(),
                    public_key: reality_settings.public_key.clone(),
                    short_ids: reality_settings.short_ids.clone(),
                    fingerprint: reality_settings.fingerprint.clone(),
                };
                Some(RealityServer::new(reality_config)?)
            } else {
                None
            }
        } else {
            None
        };


        // 创建 XHTTP 服务器 (如果启用)
        let _xhttp_server = if let Some(xhttp_settings) = &inbound.stream_settings.xhttp_settings {
            let xhttp_config = crate::transport::xhttp::XhttpConfig {
                mode: match xhttp_settings.mode {
                    crate::config::XhttpMode::StreamUp => {
                        crate::transport::xhttp::XhttpMode::StreamUp
                    }
                    crate::config::XhttpMode::StreamDown => {
                        crate::transport::xhttp::XhttpMode::StreamDown
                    }
                    crate::config::XhttpMode::StreamOne => {
                        crate::transport::xhttp::XhttpMode::StreamOne
                    }
                },
                path: xhttp_settings.path.clone(),
                host: xhttp_settings.host.clone(),
            };
            Some(XhttpServer::new(xhttp_config)?)
        } else {
            None
        };

        // 接受连接循环
        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    // 获取 sockopt 配置
                    let sockopt = &inbound.stream_settings.sockopt;
                    
                    // 应用 TCP No Delay 配置
                    if sockopt.tcp_no_delay {
                        if let Err(e) = stream.set_nodelay(true) {
                            error!("设置 TCP_NODELAY 失败: {}", e);
                        }
                    }
                    
                    info!("📥 新连接来自: {}", addr);

                    let codec = codec.clone();
                    let reality_server = reality_server.clone();
                    let connection_manager = connection_manager.clone();
                    let sniffing_enabled = inbound.settings.sniffing.enabled;
                    let tcp_no_delay = inbound.stream_settings.sockopt.tcp_no_delay;
                    let accept_proxy_protocol = inbound.stream_settings.sockopt.accept_proxy_protocol;

                    tokio::spawn(async move {
                        if let Err(e) =
                            Self::handle_client(stream, codec, reality_server, connection_manager, sniffing_enabled, tcp_no_delay, accept_proxy_protocol)
                                .await
                        {
                            error!("客户端处理失败: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("接受连接失败: {}", e);
                }
            }
        }
    }



// ... existing code ...

    /// 处理客户端连接
    async fn handle_client(
        mut stream: TcpStream,
        codec: VlessCodec,
        reality_server: Option<RealityServer>,
        connection_manager: ConnectionManager,
        sniffing_enabled: bool,
        tcp_no_delay: bool,
        accept_proxy_protocol: bool,
    ) -> Result<()> {
        // 如果启用 Proxy Protocol，先解析获取真实客户端 IP
        let _real_client_addr = if accept_proxy_protocol {
            use tokio::io::AsyncReadExt;
            let mut pp_buf = [0u8; 512];
            
            // Peek 数据来检查是否有 Proxy Protocol 头
            match stream.peek(&mut pp_buf).await {
                Ok(n) if n > 0 => {
                    if crate::protocol::is_proxy_protocol(&pp_buf[..n]) {
                        // 读取实际数据
                        let mut read_buf = vec![0u8; n];
                        stream.read_exact(&mut read_buf).await?;
                        
                        match crate::protocol::parse_proxy_protocol(&read_buf) {
                            Ok((header, consumed)) => {
                                info!("📡 Proxy Protocol: 真实客户端 IP = {}", header.source_addr);
                                // 如果还有剩余数据需要处理...
                                if consumed < read_buf.len() {
                                    // 这部分数据需要重新处理，但目前简化处理
                                    debug!("Proxy Protocol 后有 {} 字节剩余", read_buf.len() - consumed);
                                }
                                Some(header.source_addr)
                            }
                            Err(e) => {
                                warn!("Proxy Protocol 解析失败: {}", e);
                                None
                            }
                        }
                    } else {
                        None
                    }
                }
                _ => None,
            }
        } else {
            None
        };

        // 如果配置了 Reality，执行握手
        let mut stream: Box<dyn AsyncStream> = if let Some(reality) = reality_server {
            let tls_stream = reality.accept(stream).await?;
            Box::new(tls_stream)
        } else {
            Box::new(stream)
        };

        // 读取 VLESS 请求（带超时，支持多次读取）
        let mut buf = bytes::BytesMut::with_capacity(4096);
        use tokio::io::AsyncReadExt;
        use tokio::time::{timeout, Duration};
        
        // 第一次读取，5秒超时
        let read_result = timeout(Duration::from_secs(5), stream.read_buf(&mut buf)).await;
        
        match read_result {
            Ok(Ok(0)) => {
                info!("客户端在发送VLESS请求前关闭了连接");
                return Ok(());
            },
            Ok(Ok(n)) => {
                info!("📦 读取了 {} 字节的 VLESS 数据", n);
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
                // 检查是否是 HTTP 探测请求（Passwall 会在前面加协议头，所以不在开头）
                let buf_slice = &buf[..];
                let is_http_probe = buf_slice.windows(4).any(|w| 
                    w == b"GET " || w == b"POST"
                ) || buf_slice.windows(4).any(|w| w == b"HEAD");
                
                if is_http_probe {
                    // 这是 HTTP 探测请求，返回 204 响应
                    let peek_len = buf.len().min(64);
                    let peek = String::from_utf8_lossy(&buf[..peek_len]).replace("\r", "\\r").replace("\n", "\\n");
                    info!("🔍 检测到 HTTP 探测请求 ({} bytes): \"{}\"", buf.len(), peek);
                    use tokio::io::AsyncWriteExt;
                    let _ = stream.write_all(b"HTTP/1.1 204 No Content\r\n\r\n").await;
                    return Ok(());
                }
                
                // 真正的 VLESS 解码错误才记录详细日志
                let bytes_read = buf.len();
                let hex_dump = hex::encode(&buf[..bytes_read.min(128)]);
                error!("❌ VLESS 解码失败: {}. Bytes: {} Hex: {}", e, bytes_read, hex_dump);
                return Err(e);
            }
        };
        info!("📨 VLESS 请求: {:?} -> {}", request.command, request.address.to_string());

        // 发送 VLESS 响应
        let response = crate::protocol::vless::VlessResponse::new();
        let response_bytes = codec.encode_response(&response)?;
        
        use tokio::io::AsyncWriteExt;
        stream.write_all(&response_bytes).await?;

        // 根据命令类型处理
        match request.command {
            Command::Tcp => {
                let mut target_address = request.address.to_string();
                let mut initial_data = Vec::new();

                // --- 🌟 SNIFFING START ---
                // 1. 先检查之前的缓冲区是否有剩余数据 (Header 和 Payload 一起发过来的情况)
                if !buf.is_empty() {
                    initial_data.extend_from_slice(&buf);
                    buf.clear(); 
                }

                // 只有在启用嗅探时才执行嗅探逻辑
                if sniffing_enabled {

                // 2. 如果数据不够嗅探 (或为空)，再尝试从 stream 读取
                // 即使有数据，如果 ClientHello 被分包了，也可能不够。TLS ClientHello 至少几十字节。
                // 如果 initial_data 为空，肯定要读。如果不为空但很短，也可以尝试读更多(带超时)。
                // UPDATE V31: 452 bytes were insufficient for full ClientHello. Increase threshold to 2048.
                // 只要没读够完整的 ClientHello，Sniffer 就会返回 None。
                // 实际上我们应该读到 Sniffer 满意为止。但为了简单，我们只要小于 2048 字节就尝试读更多。
                if initial_data.len() < 2048 { 
                    let mut sniff_buf = vec![0u8; 4096];
                    
                    // 使用 timeout 防止阻塞 (3秒)
                    // 如果 initial_data 已有数据，我们只读更短时间？或者依然读？
                    // 简单起见，尝试读一次。
                    let timeout_dur = if initial_data.is_empty() { 
                        std::time::Duration::from_millis(3000) 
                    } else {
                        // 如果已有部分数据，等待后续数据的时间可以短一点
                        std::time::Duration::from_millis(500)
                    };

                    match tokio::time::timeout(timeout_dur, stream.read(&mut sniff_buf)).await {
                        Ok(Ok(n)) => {
                            if n > 0 {
                                initial_data.extend_from_slice(&sniff_buf[..n]);
                            }
                        },
                        Ok(Err(e)) => {
                            error!("Failed to sniff initial data: {}", e);
                            return Err(e.into());
                        },
                        Err(_) => {
                            // Timeout
                            if initial_data.is_empty() {
                                debug!("Sniffing timed out (empty data), proceeding with original address");
                            } else {
                                // 已经有部分数据了，就不算完全超时
                            }
                        }
                    }
                }

                // 3. 尝试嗅探
                if !initial_data.is_empty() {
                     if let Some(sni) = crate::protocol::sniffer::sniff_tls_sni(&initial_data) {
                        // 提取端口 (手动匹配 Address 枚举)
                        let port = match &request.address {
                            crate::protocol::vless::Address::Ipv4(_, p) => *p,
                            crate::protocol::vless::Address::Domain(_, p) => *p,
                            crate::protocol::vless::Address::Ipv6(_, p) => *p,
                        };
                        
                        info!("🕵️ Sniffed domain: {} (Override original: {})", sni, target_address);
                        target_address = format!("{}:{}", sni, port);
                    } else {
                        // 只有在数据足够长时才认为是 "No SNI found"，否则可能是太短
                        let len = initial_data.len();
                        debug!("No SNI found in initial data ({} bytes)", len);
                        if len > 0 {
                            // 打印前 32 字节 Hex 以供调试，看看这到底是啥
                            let dump_len = std::cmp::min(len, 64);
                            error!("📦 Hex Dump (First {} bytes): {:02X?}", dump_len, &initial_data[..dump_len]);
                        }
                    }
                }
                } // if sniffing_enabled
                // --- 🌟 SNIFFING END ---

                // 连接到目标服务器 (可能是原来的 IP，也可能是嗅探到的域名)
                let mut remote_stream = match TcpStream::connect(&target_address).await {
                    Ok(s) => s,
                    Err(e) => {
                        error!("无法连接到目标 {}: {}", target_address, e);
                        return Err(e.into());
                    }
                };
                
                // 优化远程连接的 TCP 设置
                if tcp_no_delay {
                    if let Err(e) = remote_stream.set_nodelay(true) {
                        error!("设置远程 TCP_NODELAY 失败: {}", e);
                    }
                }
                
                info!("🔗 已连接到远程: {}", target_address);

                // 如果我们预读取了数据，必须先发给远程服务器
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
                
                // 创建 UDP socket (Full Cone NAT - 不绑定到特定目标)
                let udp_socket = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
                    Ok(s) => s,
                    Err(e) => {
                        error!("无法创建 UDP socket: {}", e);
                        return Err(e.into());
                    }
                };
                
                // 解析目标地址 (初始目标，Full Cone 模式下可接收任意地址响应)
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
                
                // UDP 会话超时配置 (5分钟)
                let session_timeout = tokio::time::Duration::from_secs(300);
                
                let udp_socket = std::sync::Arc::new(udp_socket);
                let udp_socket_recv = udp_socket.clone();
                
                // 预读取的数据作为第一个 UDP 包发送
                if !buf.is_empty() {
                    // 解析 VLESS UDP 帧: [2 bytes length] [payload]
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
                
                // 使用 tokio::select! 同时处理两个方向的数据
                let (mut stream_read, mut stream_write) = tokio::io::split(stream);
                let initial_target_clone = initial_target;
                
                // 客户端 -> UDP 目标
                let send_task = async {
                    let mut read_buf = vec![0u8; 65536];
                    let mut last_activity = tokio::time::Instant::now();
                    
                    loop {
                        // 带超时的读取
                        let read_timeout = session_timeout.saturating_sub(last_activity.elapsed());
                        
                        let mut len_buf = [0u8; 2];
                        match tokio::time::timeout(
                            read_timeout,
                            tokio::io::AsyncReadExt::read_exact(&mut stream_read, &mut len_buf)
                        ).await {
                            Ok(Ok(_)) => {
                                last_activity = tokio::time::Instant::now();
                                let len = ((len_buf[0] as usize) << 8) | (len_buf[1] as usize);
                                
                                if len == 0 || len > read_buf.len() {
                                    if len > read_buf.len() {
                                        error!("UDP 包太大: {}", len);
                                    }
                                    break;
                                }
                                
                                match tokio::io::AsyncReadExt::read_exact(&mut stream_read, &mut read_buf[..len]).await {
                                    Ok(_) => {
                                        // Full Cone: 使用 send_to 而不是 send
                                        if let Err(e) = udp_socket.send_to(&read_buf[..len], initial_target_clone).await {
                                            error!("UDP 发送失败: {}", e);
                                            break;
                                        }
                                        debug!("UDP 发送了 {} 字节 -> {}", len, initial_target_clone);
                                    }
                                    Err(e) => {
                                        debug!("读取 UDP 载荷失败: {}", e);
                                        break;
                                    }
                                }
                            }
                            Ok(Err(e)) => {
                                debug!("UDP 流结束: {}", e);
                                break;
                            }
                            Err(_) => {
                                debug!("UDP 会话超时 (客户端方向)");
                                break;
                            }
                        }
                    }
                };
                
                // UDP 目标 -> 客户端 (Full Cone: 接收任意地址的响应)
                let recv_task = async {
                    let mut recv_buf = vec![0u8; 65536];
                    let mut last_activity = tokio::time::Instant::now();
                    
                    loop {
                        let recv_timeout = session_timeout.saturating_sub(last_activity.elapsed());
                        
                        match tokio::time::timeout(
                            recv_timeout,
                            udp_socket_recv.recv_from(&mut recv_buf)  // Full Cone: recv_from 接收任意地址
                        ).await {
                            Ok(Ok((n, from_addr))) => {
                                if n == 0 {
                                    break;
                                }
                                last_activity = tokio::time::Instant::now();
                                
                                debug!("UDP 收到 {} 字节 <- {}", n, from_addr);
                                
                                // 封装成 VLESS UDP 帧发回客户端
                                // [2 bytes length] [payload]
                                let len_bytes = [(n >> 8) as u8, (n & 0xff) as u8];
                                
                                use tokio::io::AsyncWriteExt;
                                
                                // 使用单次 write 优化，减少系统调用
                                let mut frame = Vec::with_capacity(2 + n);
                                frame.extend_from_slice(&len_bytes);
                                frame.extend_from_slice(&recv_buf[..n]);
                                
                                if let Err(e) = stream_write.write_all(&frame).await {
                                    error!("UDP 响应写入失败: {}", e);
                                    break;
                                }
                                
                                // 立即 flush 以降低延迟
                                if let Err(e) = stream_write.flush().await {
                                    error!("UDP 响应 flush 失败: {}", e);
                                    break;
                                }
                            }
                            Ok(Err(e)) => {
                                error!("UDP 接收失败: {}", e);
                                break;
                            }
                            Err(_) => {
                                debug!("UDP 会话超时 (服务器方向)");
                                break;
                            }
                        }
                    }
                };
                
                // 同时运行发送和接收任务，任一结束则全部结束
                tokio::select! {
                    _ = send_task => {
                        debug!("UDP 发送任务结束");
                    }
                    _ = recv_task => {
                        debug!("UDP 接收任务结束");
                    }
                }
                
                info!("📡 UDP 会话结束");
            }
            Command::Mux => {
                warn!("Mux 暂不支持");
            }
        }

        Ok(())
    }
}


