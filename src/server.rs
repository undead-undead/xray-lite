use anyhow::Result;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{error, info, warn, debug};
use uuid::Uuid;

use crate::config::{Config, Inbound, Security};
use crate::network::ConnectionManager;
use crate::protocol::vless::{Command, VlessCodec};
use crate::transport::{RealityServer, XhttpServer};
use crate::handler::serve_vless;

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
                    crate::config::XhttpMode::Auto => {
                        crate::transport::xhttp::XhttpMode::Auto
                    }
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

        // 连接数限制 (防止 OOM)
        const MAX_CONNECTIONS: usize = 4096;
        let connection_semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
        
        info!("🔒 最大并发连接数: {}", MAX_CONNECTIONS);

        // 接受连接循环
        loop {
            // 获取连接许可
            let permit = match connection_semaphore.clone().acquire_owned().await {
                Ok(p) => p,
                Err(_) => {
                    error!("连接限制信号量已关闭");
                    return Ok(());
                }
            };
            
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
                    let _xhttp_server = _xhttp_server.clone();
                    let sniffing_enabled = inbound.settings.sniffing.enabled;
                    let tcp_no_delay = inbound.stream_settings.sockopt.tcp_no_delay;
                    let accept_proxy_protocol = inbound.stream_settings.sockopt.accept_proxy_protocol;

                    tokio::spawn(async move {
                        // 持有 permit 直到连接结束，自动释放
                        let _permit = permit;
                        
                        if let Err(e) =
                            Self::handle_client(stream, codec, reality_server, _xhttp_server, connection_manager, sniffing_enabled, tcp_no_delay, accept_proxy_protocol)
                                .await
                        {
                            error!("客户端处理失败: {}", e);
                        }
                        // permit 在这里自动 drop，释放连接槽
                    });
                }
                Err(e) => {
                    error!("接受连接失败: {}", e);
                }
            }
        }
    }

    /// 处理客户端连接
    async fn handle_client(
        mut stream: TcpStream,
        codec: VlessCodec,
        reality_server: Option<RealityServer>,
        xhttp_server: Option<XhttpServer>,
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
                            Ok((header, _consumed)) => {
                                info!("📡 Proxy Protocol: 真实客户端 IP = {}", header.source_addr);
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
        let stream: Box<dyn AsyncStream> = if let Some(reality) = reality_server {
            let tls_stream = reality.accept(stream).await?;
            Box::new(tls_stream)
        } else {
            Box::new(stream)
        };

        // 定义 VLESS 处理回调
        let codec_clone = codec.clone();
        let connection_manager_clone = connection_manager.clone(); 
        
        let vless_handler = move |stream: Box<dyn AsyncStream>| {
            let codec = codec_clone.clone();
            let connection_manager = connection_manager_clone.clone();
            async move {
                serve_vless(stream, codec, connection_manager, sniffing_enabled, tcp_no_delay).await
            }
        };

        // 如果配置了 XHTTP，使用 XHTTP 处理
        if let Some(xhttp) = xhttp_server {
            xhttp.accept(stream, vless_handler).await?;
        } else {
            // 标准 TCP 模式，直接处理 VLESS
            vless_handler(stream).await?;
        }

        Ok(())
    }
}
