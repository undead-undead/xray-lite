use anyhow::Result;
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info, warn};
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
        let listener = TcpListener::bind(&addr).await?;

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
                    // 优化 TCP socket 设置
                    if let Err(e) = stream.set_nodelay(true) {
                        error!("设置 TCP_NODELAY 失败: {}", e);
                    }
                    
                    info!("📥 新连接来自: {}", addr);

                    let codec = codec.clone();
                    let reality_server = reality_server.clone();
                    let connection_manager = connection_manager.clone();

                    tokio::spawn(async move {
                        if let Err(e) =
                            Self::handle_client(stream, codec, reality_server, connection_manager)
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
        stream: TcpStream,
        codec: VlessCodec,
        reality_server: Option<RealityServer>,
        connection_manager: ConnectionManager,
    ) -> Result<()> {
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
                    use tokio::io::AsyncWriteExt;
                    let _ = stream.write_all(b"HTTP/1.1 204 No Content\r\n\r\n").await;
                    return Ok(());
                }
                
                // 真正的 VLESS 解码错误才记录详细日志
                let bytes_read = buf.len();
                let hex_dump = hex::encode(&buf[..bytes_read.min(128)]);
                error!("VLESS 解码失败: {}. Bytes: {} Hex: {}", e, bytes_read, hex_dump);
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
                // 连接到目标服务器
                let remote_stream = TcpStream::connect(request.address.to_string()).await?;
                
                // 优化远程连接的 TCP 设置
                if let Err(e) = remote_stream.set_nodelay(true) {
                    error!("设置远程 TCP_NODELAY 失败: {}", e);
                }
                
                info!("🔗 已连接到远程: {}", request.address.to_string());

                // 开始双向转发
                connection_manager
                    .handle_connection(stream, remote_stream)
                    .await?;
            }
            Command::Udp => {
                warn!("UDP 暂不支持");
            }
            Command::Mux => {
                warn!("Mux 暂不支持");
            }
        }

        Ok(())
    }
}


