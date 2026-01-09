/// Reality server implementation using rustls-reality
///
/// This implementation provides "Sniff-and-Dispatch" capability for xray-lite integration.

use std::sync::Arc;
use anyhow::{Result, anyhow, bail};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;
use rustls::ServerConfig;
use rustls::reality::RealityConfig;
// Imports for rustls v0.22
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tracing::{info, debug, error, warn};

use super::hello_parser;

#[derive(Clone)]
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

        // Generate a self-signed certificate for the destination
        // In a real Reality implementation, this should be the "stolen" certificate.
        // For now, we generate one to allow the TLS handshake to complete.
        // TODO: Implement certificate stealing/forwarding from dest.
        
        let subject_alt_names = vec!["www.microsoft.com".to_string()];
        let cert = rcgen::generate_simple_self_signed(subject_alt_names)
            .map_err(|e| anyhow!("Failed to generate self-signed cert: {}", e))?;
            
        let cert_der = cert.serialize_der()
            .map_err(|e| anyhow!("Failed to serialize cert: {}", e))?;
        let key_der = cert.serialize_private_key_der();

        let certs = vec![CertificateDer::from(cert_der)];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));

        // rustls 0.22 builder pattern
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| anyhow!("Failed to create ServerConfig: {}", e))?;

        let mut config = config;
        config.reality_config = Some(Arc::new(reality_config.clone()));

        let acceptor = TlsAcceptor::from(Arc::new(config));

        Ok(Self { 
            acceptor,
            reality_config: Arc::new(reality_config),
        })
    }

    /// Accept a connection.
    /// Returns Ok(stream) if valid Reality connection.
    /// Returns Err if connection was rejected or handled via fallback.
    pub async fn accept(&self, mut stream: TcpStream) -> Result<tokio_rustls::server::TlsStream<TcpStream>> {
        let mut buf = vec![0u8; 1024];
        let n = stream.peek(&mut buf).await?;
        if n == 0 {
            bail!("Connection closed during peek");
        }
        
        let peek_slice = &buf[..n];
        let should_fallback = match hello_parser::parse_client_hello(peek_slice) {
            Ok(Some(info)) => !rustls::reality::verify_client(&info.session_id, &info.client_random, &self.reality_config),
            Ok(None) => true, // Not ClientHello
            Err(_) => true // Parse error
        };

        if should_fallback {
            let dest = self.reality_config.dest.as_ref().unwrap();
            info!("Non-Reality client detected, falling back to {}", dest);
            
            // Execute fallback
            // This will block until the fallback connection is finished/closed
            if let Err(e) = self.fallback(stream, dest).await {
                warn!("Fallback error: {}", e);
            }
            
            // Return error indicating this connection is handled/not for VLESS
            bail!("Reality fallback handled");
        } else {
            info!("Reality client detected, proceeding with handshake");
            // Pass to rustls
            let tls_stream = self.acceptor.accept(stream).await?;
            info!("Reality handshake successful");
            Ok(tls_stream)
        }
    }

    async fn fallback(&self, mut stream: TcpStream, dest_addr: &str) -> Result<()> {
        let mut dest_stream = TcpStream::connect(dest_addr).await?;
        let _ = stream.set_nodelay(true);
        let _ = dest_stream.set_nodelay(true);

        let (mut client_read, mut client_write) = stream.split();
        let (mut dest_read, mut dest_write) = dest_stream.split();
        
        let client_to_dest = tokio::io::copy(&mut client_read, &mut dest_write);
        let dest_to_client = tokio::io::copy(&mut dest_read, &mut client_write);
        
        let _ = tokio::try_join!(client_to_dest, dest_to_client);
        Ok(())
    }
    
    // Test helper
    pub fn test_inject_auth(&self, server_random: &mut [u8; 32], client_random: &[u8; 32]) -> Result<()> {
        rustls::reality::inject_auth(server_random, &self.reality_config, client_random)
            .map_err(|e| anyhow!("Failed to inject Reality auth: {:?}", e))
    }
}
