/// Reality server implementation using rustls-reality
///
/// This implementation provides "Sniff-and-Dispatch" capability:
/// 1. Peeks at the first packet (ClientHello)
/// 2. Verifies Reality authentication
/// 3. If valid: Dispatches to rustls for Reality handshake
/// 4. If invalid: Fallbacks/Proxies to destination server

use std::sync::Arc;
use anyhow::{Result, anyhow};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use rustls::ServerConfig;
use rustls::reality::RealityConfig;
// Imports for rustls v0.22 (used by tokio-rustls 0.25)
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tracing::{info, debug, error, warn};

use super::hello_parser;

pub struct RealityServerRustls {
    acceptor: TlsAcceptor,
    reality_config: Arc<RealityConfig>,
}

impl RealityServerRustls {
    /// Create a new Reality server with rustls
    pub fn new(private_key: Vec<u8>, dest: Option<String>) -> Result<Self> {
        let reality_config = RealityConfig::new(private_key)
            .with_verify_client(true)
            .with_dest(dest.unwrap_or_else(|| "www.microsoft.com:443".to_string()));

        reality_config.validate()?;

        // rustls 0.22 builder pattern
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(DummyCertResolver));

        let mut config = config;
        config.reality_config = Some(Arc::new(reality_config.clone()));

        let acceptor = TlsAcceptor::from(Arc::new(config));

        Ok(Self { 
            acceptor,
            reality_config: Arc::new(reality_config),
        })
    }

    pub fn config(&self) -> &Arc<RealityConfig> {
        &self.reality_config
    }
    
    pub fn test_inject_auth(&self, server_random: &mut [u8; 32], client_random: &[u8; 32]) -> Result<()> {
        rustls::reality::inject_auth(server_random, &self.reality_config, client_random)
            .map_err(|e| anyhow!("Failed to inject Reality auth: {:?}", e))
    }

    pub async fn run(&self, addr: &str) -> Result<()> {
        let listener = TcpListener::bind(addr).await?;
        info!("Reality server listening on {}", addr);

        loop {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    info!("New connection from {}", peer_addr);
                    let acceptor = self.acceptor.clone();
                    let config = self.reality_config.clone();
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_connection(stream, acceptor, config).await {
                            error!("Connection handling failed: {}", e);
                        }
                    });
                }
                Err(e) => error!("Failed to accept connection: {}", e),
            }
        }
    }

    async fn handle_connection(
        mut stream: TcpStream, 
        acceptor: TlsAcceptor, 
        config: Arc<RealityConfig>
    ) -> Result<()> {
        let mut buf = vec![0u8; 1024];
        let n = stream.peek(&mut buf).await?;
        if n == 0 { return Ok(()); }
        
        // Try parsing only what we have peeked
        let peek_slice = &buf[..n];
        let should_fallback = match hello_parser::parse_client_hello(peek_slice) {
            Ok(Some(info)) => !rustls::reality::verify_client(&info.session_id, &info.client_random, &config),
            Ok(None) => true, // Not ClientHello
            Err(_) => true // Parse error
        };

        if should_fallback {
            info!("Non-Reality client detected ({}), falling back", stream.peer_addr().unwrap());
            Self::fallback(stream, &config.dest.as_ref().unwrap()).await?;
        } else {
            info!("Reality client detected ({}), proceeding with handshake", stream.peer_addr().unwrap());
            match acceptor.accept(stream).await {
                Ok(_tls_stream) => {
                    info!("Reality handshake successful");
                    // TODO: Handle VLESS
                }
                Err(e) => {
                    error!("Reality handshake error: {}", e);
                }
            }
        }
        Ok(())
    }

    async fn fallback(mut stream: TcpStream, dest_addr: &str) -> Result<()> {
        let mut dest_stream = TcpStream::connect(dest_addr).await?;
        let (mut client_read, mut client_write) = stream.split();
        let (mut dest_read, mut dest_write) = dest_stream.split();
        let client_to_dest = tokio::io::copy(&mut client_read, &mut dest_write);
        let dest_to_client = tokio::io::copy(&mut dest_read, &mut client_write);
        let _ = tokio::try_join!(client_to_dest, dest_to_client);
        Ok(())
    }
}

#[derive(Debug)]
struct DummyCertResolver;
impl ResolvesServerCert for DummyCertResolver {
    fn resolve(
        &self,
        _client_hello: ClientHello,
    ) -> Option<Arc<CertifiedKey>> {
        None
    }
}
