use anyhow::Result;
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::config::{Config, Inbound, Security};
use crate::network::ConnectionManager;
use crate::protocol::vless::{Command, VlessCodec};
use crate::transport::{RealityServer, XhttpServer};

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

    /// 处理客户端连接
    async fn handle_client(
        stream: TcpStream,
        codec: VlessCodec,
        reality_server: Option<RealityServer>,
        connection_manager: ConnectionManager,
    ) -> Result<()> {
        // 如果启用了 Reality，先处理 TLS 握手
        let mut stream = if let Some(reality) = reality_server {
            reality.accept(stream).await?
        } else {
            stream
        };

        // 读取 VLESS 请求
        let mut buf = bytes::BytesMut::with_capacity(4096);
        use tokio::io::AsyncReadExt;
        stream.read_buf(&mut buf).await?;

        let request = codec.decode_request(&mut buf)?;
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


