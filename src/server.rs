use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{ReadBuf, AsyncRead, AsyncWrite};
use bytes::Buf;
use anyhow::Result;
use tokio::net::TcpListener;
use tracing::{error, info};
use uuid::Uuid;

use crate::config::{Config, Inbound, Security};
use crate::network::ConnectionManager;
use crate::protocol::vless::VlessCodec;
use crate::transport::{RealityServer, XhttpServer};
use crate::handler::serve_vless;

/// 定义通用的 AsyncStream trait 以支持 TCP 和 TLS 流
pub trait AsyncStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + crate::utils::net::MaybeAsRawFd + Unpin + 'static {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + crate::utils::net::MaybeAsRawFd + Unpin + 'static> AsyncStream for T {}

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
        for inbound in self.config.inbounds.clone() {
            let connection_manager = self.connection_manager.clone();
            
            crate::utils::task::spawn(async move {
                if let Err(e) = Self::run_inbound(inbound, connection_manager).await {
                    error!("入站处理失败: {}", e);
                }
            });
        }

        // 保持主任务存活
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
        }
    }

    async fn run_inbound(inbound: Inbound, connection_manager: ConnectionManager) -> Result<()> {
        let addr = format!("{}:{}", inbound.listen, inbound.port);
        let listener = TcpListener::bind(&addr).await?;

        info!("🎯 监听 {} (协议: {:?})", addr, inbound.protocol);

        let uuids: Vec<Uuid> = inbound
            .settings
            .clients
            .iter()
            .filter_map(|c| Uuid::parse_str(&c.id).ok())
            .collect();
        let codec = VlessCodec::new(uuids);

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

        let xhttp_server = if let Some(xhttp_settings) = &inbound.stream_settings.xhttp_settings {
            let xhttp_config = crate::transport::xhttp::XhttpConfig {
                mode: match xhttp_settings.mode {
                    crate::config::XhttpMode::Auto => crate::transport::xhttp::XhttpMode::Auto,
                    crate::config::XhttpMode::StreamUp => crate::transport::xhttp::XhttpMode::StreamUp,
                    crate::config::XhttpMode::StreamDown => crate::transport::xhttp::XhttpMode::StreamDown,
                    crate::config::XhttpMode::StreamOne => crate::transport::xhttp::XhttpMode::StreamOne,
                },
                path: xhttp_settings.path.clone(),
                host: xhttp_settings.host.clone(),
            };
            Some(XhttpServer::new(xhttp_config)?)
        } else {
            None
        };

        // 连接数限制 (防止 OOM)
        const MAX_CONNECTIONS: usize = 10000;
        let connection_semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
        info!("🔒 最大并发连接数: {}", MAX_CONNECTIONS);

        loop {
            // 获取连接许可
            let permit = match connection_semaphore.clone().acquire_owned().await {
                Ok(p) => p,
                Err(_) => break,
            };

            match listener.accept().await {
                Ok((stream, addr)) => {
                    info!("📥 新连接来自: {}", addr);
                    let codec = codec.clone();
                    let reality_server = reality_server.clone();
                    let xhttp_server = xhttp_server.clone();
                    let connection_manager = connection_manager.clone();
                    let sniffing_enabled = inbound.settings.sniffing.enabled;
                    let tcp_no_delay = inbound.stream_settings.sockopt.tcp_no_delay;
                    let accept_proxy_protocol = inbound.stream_settings.sockopt.accept_proxy_protocol;

                    crate::utils::task::spawn(async move {
                        let _permit = permit; // 持有 permit 直到连接结束
                        if let Err(e) = Self::handle_client(stream, codec, reality_server, xhttp_server, connection_manager, sniffing_enabled, tcp_no_delay, accept_proxy_protocol).await {
                            error!("客户端处理失败: {}", e);
                        }
                    });
                }
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        continue;
                    }
                    if e.raw_os_error() == Some(24) { // EMFILE
                        error!("❌ 系统文件句柄耗尽 (EMFILE)，等待 1 秒...");
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        continue;
                    }
                    error!("接受连接失败: {}", e);
                }
            }
        }
    }

    pub async fn handle_client<S>(
        mut stream: S,
        codec: VlessCodec,
        reality_server: Option<RealityServer>,
        xhttp_server: Option<XhttpServer>,
        connection_manager: ConnectionManager,
        sniffing_enabled: bool,
        tcp_no_delay: bool,
        accept_proxy_protocol: bool,
    ) -> Result<()> 
    where S: AsyncRead + AsyncWrite + Unpin + 'static + crate::utils::net::MaybeAsRawFd
    {
        // 1. Proxy Protocol
        let (stream, _real_addr): (Box<dyn AsyncStream>, _) = if accept_proxy_protocol {
            use tokio::io::AsyncReadExt;
            let mut buf = vec![0u8; 16];
            match stream.read(&mut buf).await {
                Ok(n) if n > 0 && crate::protocol::is_proxy_protocol(&buf[..n]) => {
                    let mut full = buf[..n].to_vec();
                    let mut rest = vec![0u8; 128];
                    if let Ok(rn) = stream.read(&mut rest).await { full.extend_from_slice(&rest[..rn]); }
                    match crate::protocol::parse_proxy_protocol(&full) {
                        Ok((h, c)) => (Box::new(PrefixedStream::new(full[c..].to_vec(), stream)), Some(h.source_addr)),
                        Err(_) => (Box::new(PrefixedStream::new(full, stream)), None),
                    }
                },
                Ok(n) if n > 0 => (Box::new(PrefixedStream::new(buf[..n].to_vec(), stream)), None),
                _ => (Box::new(stream), None),
            }
        } else {
            (Box::new(stream), None)
        };

        // 2. Reality
        let stream: Box<dyn AsyncStream> = if let Some(reality) = reality_server {
            Box::new(reality.accept(stream).await?)
        } else {
            stream
        };

        // 3. XHTTP or VLESS
        let codec_clone = codec.clone();
        let connection_manager_clone = connection_manager.clone();
        let vless_handler = move |s: Box<dyn AsyncStream>| {
            let c = codec_clone.clone();
            let m = connection_manager_clone.clone();
            async move { serve_vless(s, c, m, sniffing_enabled, tcp_no_delay).await }
        };

        if let Some(xhttp) = xhttp_server {
            xhttp.accept(stream, vless_handler).await?;
        } else {
            vless_handler(stream).await?;
        }
        Ok(())
    }
}

pub struct PrefixedStream<S> {
    prefix: std::io::Cursor<Vec<u8>>,
    inner: S,
}

impl<S> PrefixedStream<S> {
    pub fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self { prefix: std::io::Cursor::new(prefix), inner }
    }
}

impl<S: crate::utils::net::MaybeAsRawFd> crate::utils::net::MaybeAsRawFd for PrefixedStream<S> {
    fn maybe_as_raw_fd(&self) -> Option<std::os::fd::RawFd> {
        self.inner.maybe_as_raw_fd()
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        if self.prefix.has_remaining() {
            let n = std::cmp::min(buf.remaining(), self.prefix.remaining());
            let pos = self.prefix.position() as usize;
            buf.put_slice(&self.prefix.get_ref()[pos..pos + n]);
            self.prefix.set_position((pos + n) as u64);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
