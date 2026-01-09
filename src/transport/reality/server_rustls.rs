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

// Imports for PrefixedStream & Read Logic
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf, AsyncReadExt, AsyncWriteExt};
use std::io::Cursor;
use bytes::Buf;

// Crypto imports for verification
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use hkdf::Hkdf;
use sha2::Sha256;
use aes_gcm::{Aes256Gcm, KeyInit, AeadInPlace, Nonce};

use super::hello_parser::{self, ClientHelloInfo};

#[derive(Clone)]
pub struct RealityServerRustls {
    acceptor: TlsAcceptor,
    reality_config: Arc<RealityConfig>,
}

impl RealityServerRustls {
    /// Create a new Reality server with rustls
    pub fn new(private_key: Vec<u8>, dest: Option<String>, short_ids: Vec<String>) -> Result<Self> {
        let mut short_ids_bytes = Vec::new();
        for id in short_ids {
            let b = hex::decode(&id).map_err(|e| anyhow!("Invalid shortId hex: {}", e))?;
            short_ids_bytes.push(b);
        }

        let reality_config = RealityConfig::new(private_key)
            .with_verify_client(true)
            .with_short_ids(short_ids_bytes)
            .with_dest(dest.unwrap_or_else(|| "www.microsoft.com:443".to_string()));

        reality_config.validate()?;

        // Generate a self-signed certificate for the destination
        let dest_str = reality_config.dest.as_deref().unwrap_or("www.microsoft.com");
        let dest_host = dest_str.split(':').next().unwrap_or("www.microsoft.com");
        let subject_alt_names = vec![dest_host.to_string()];
        
        // Note: rcgen must be in dependencies
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
    pub async fn accept(&self, mut stream: TcpStream) -> Result<tokio_rustls::server::TlsStream<PrefixedStream<TcpStream>>> {
        // Robust reading loop: Read until we have enough for a TLS Record header, then read the full record.
        let mut buffer = Vec::with_capacity(4096);
        
        // 1. Read TLS Header (5 bytes)
        while buffer.len() < 5 {
            let mut chunk = [0u8; 1024];
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                if buffer.is_empty() {
                    bail!("Connection closed empty");
                }
                break; 
            }
            buffer.extend_from_slice(&chunk[..n]);
        }

        // 2. Check header to determine needed length
        let mut needed = buffer.len(); // Default to what we have if not TLS
        if buffer.len() >= 5 && buffer[0] == 0x16 {
            // It's a Handshake record
            let len = u16::from_be_bytes([buffer[3], buffer[4]]) as usize;
            needed = 5 + len;
        }

        // 3. Read until we have the full record (or hit a sane limit)
        let limit = 16384; 
        while buffer.len() < needed && buffer.len() < limit {
             let mut chunk = [0u8; 1024];
             let n = stream.read(&mut chunk).await?;
             if n == 0 { break; }
             buffer.extend_from_slice(&chunk[..n]);
        }

        let full_client_hello = &buffer;
        
        // Try parsing
        let parse_result = hello_parser::parse_client_hello(full_client_hello);

        let should_fallback = match parse_result {
            Ok(Some(info)) => {
                 if !self.verify_client_reality(&info, full_client_hello) {
                     true
                 } else {
                     false 
                 }
            },
            Ok(None) => {
                info!("Fallback decision: Not a recognized TLS ClientHello. Len: {}, Header: {:02x?}", full_client_hello.len(), if full_client_hello.len() > 0 { &full_client_hello[0..std::cmp::min(5, full_client_hello.len())] } else { &[] });
                true
            }, 
            Err(e) => {
                error!("Fallback decision: ClientHello parsing error: {}", e);
                true
            }
        };

        if should_fallback {
            let dest = self.reality_config.dest.as_deref().unwrap_or("www.microsoft.com:443");
            info!("Non-Reality or Invalid client detected from {}, falling back to {}", stream.peer_addr().unwrap_or_else(|_| "unknown".parse().unwrap()), dest);
            
            if let Err(e) = self.fallback(stream, &buffer, dest).await {
                warn!("Fallback error: {}", e);
            }
            bail!("Reality fallback handled");
        } else {
            info!("Reality client verified, proceeding with handshake");
            // Wrap stream with prefix
            let prefixed = PrefixedStream::new(buffer, stream);
            let tls_stream = self.acceptor.accept(prefixed).await?;
            info!("Reality handshake successful");
            Ok(tls_stream)
        }
    }

    /// Verifies Reality Client Authentication
    fn verify_client_reality(&self, info: &ClientHelloInfo, full_client_hello: &[u8]) -> bool {
        // 1. SessionID check
        if info.session_id.len() != 32 { return false; }
        
        let client_pub_key_bytes = match &info.public_key {
            Some(pk) => pk,
            None => return false,
        };

        if client_pub_key_bytes.len() != 32 { return false; }
        
        let mut server_priv_bytes = [0u8; 32];
        if self.reality_config.private_key.len() != 32 { return false; }
        server_priv_bytes.copy_from_slice(&self.reality_config.private_key);
        let server_secret = StaticSecret::from(server_priv_bytes);
        
        let mut client_pub_bytes = [0u8; 32];
        client_pub_bytes.copy_from_slice(client_pub_key_bytes);
        let client_public = X25519PublicKey::from(client_pub_bytes);

        let shared_secret = server_secret.diffie_hellman(&client_public);
        
        let hk = Hkdf::<Sha256>::new(
            Some(&info.client_random), // Salt = Client Random
            shared_secret.as_bytes()   // IKM = Shared Secret
        );
        let mut auth_key = [0u8; 32];
        if hk.expand(b"REALITY", &mut auth_key).is_err() { return false; }

        let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&auth_key);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(&info.client_random[20..32]);

        // AAD Strategy: Try both full and no-header
        let aad_full = full_client_hello;
        let aad_no_head = if full_client_hello.len() > 5 && full_client_hello[0] == 0x16 { 
            &full_client_hello[5..] 
        } else { 
            full_client_hello 
        };

        // I need 'buffer' to hold decrypted content outside the if/else to check ShortId
        let mut buffer = info.session_id.clone();
        
        // Re-do cleanly
        let mut success = false;
        
        // Try Full AAD
        if cipher.decrypt_in_place(nonce, aad_full, &mut buffer).is_ok() {
            success = true;
        } else {
             // Reset buffer
             buffer = info.session_id.clone();
             // Try No-Head AAD
             if cipher.decrypt_in_place(nonce, aad_no_head, &mut buffer).is_ok() {
                 success = true;
                 debug!("Reality Verified using AAD without header");
             }
        }

        if !success {
            warn!("Reality verification failed: AEAD Decrypt error. Check Key match.");
            return false;
        }
        
        if buffer.len() < 12 { 
            warn!("Reality verification failed: Decrypted payload too short");
            return false; 
        }
        let short_id_bytes = &buffer[4..12]; 
        
        let mut found = false;
        for param_id in &self.reality_config.short_ids {
            if param_id == short_id_bytes {
                found = true;
                break;
            }
        }
        
        if !found {
            warn!("Reality verification failed: ShortId mismatch. Got: {}", hex::encode(short_id_bytes));
        }

        found
    }

    async fn fallback(&self, mut stream: TcpStream, prefix: &[u8], dest_addr: &str) -> Result<()> {
        let mut dest_stream = TcpStream::connect(dest_addr).await?;
        let _ = stream.set_nodelay(true);
        let _ = dest_stream.set_nodelay(true);

        if !prefix.is_empty() {
            dest_stream.write_all(prefix).await?;
        }

        let (mut client_read, mut client_write) = stream.split();
        let (mut dest_read, mut dest_write) = dest_stream.split();
        
        let client_to_dest = tokio::io::copy(&mut client_read, &mut dest_write);
        let dest_to_client = tokio::io::copy(&mut dest_read, &mut client_write);
        
        let _ = tokio::try_join!(client_to_dest, dest_to_client);
        Ok(())
    }
}

pub struct PrefixedStream<S> {
    prefix: Cursor<Vec<u8>>,
    inner: S,
}

impl<S> PrefixedStream<S> {
    pub fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self { prefix: Cursor::new(prefix), inner }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.prefix.has_remaining() {
            let pos = self.prefix.position() as usize;
            let b = self.prefix.get_ref();
            let avail = b.len() - pos;
            let dst_len = std::cmp::min(avail, buf.remaining());
            
            buf.put_slice(&b[pos..pos+dst_len]);
            self.prefix.set_position((pos + dst_len) as u64);
            Poll::Ready(Ok(()))
        } else {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
