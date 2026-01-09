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
        // 1. SessionID check (Ciphertext)
        if info.session_id.len() != 32 { return false; }
        
        // DEBUG: Log handshake for offset verification
        debug!("Reality Debug: full_client_hello len: {}", full_client_hello.len());
        debug!("Reality Debug: full_client_hello (start): {}", hex::encode(&full_client_hello[..std::cmp::min(100, full_client_hello.len())]));
        debug!("Reality Debug: extracted session_id: {}", hex::encode(&info.session_id));
        debug!("Reality Debug: extracted client_random: {}", hex::encode(&info.client_random));

        let client_pub_key_bytes = match &info.public_key {
            Some(pk) => pk,
            None => {
                warn!("Reality verification failed: No X25519 Public Key found in ClientHello");
                return false;
            },
        };

        if client_pub_key_bytes.len() != 32 { return false; }
        
        // 2. ECDH
        let mut server_priv_bytes = [0u8; 32];
        if self.reality_config.private_key.len() != 32 { return false; }
        server_priv_bytes.copy_from_slice(&self.reality_config.private_key);
        let server_secret = StaticSecret::from(server_priv_bytes);
        
        let mut client_pub_bytes = [0u8; 32];
        client_pub_bytes.copy_from_slice(client_pub_key_bytes);
        let client_public = X25519PublicKey::from(client_pub_bytes);

        let shared_secret = server_secret.diffie_hellman(&client_public);
        debug!("Reality Debug: shared_secret: {}", hex::encode(shared_secret.as_bytes()));
        
        // 3. HKDF (SHA256)
        // Correct Reality logic: Salt is first 20 bytes of Random
        let salt = &info.client_random[0..20];
        let hk = Hkdf::<Sha256>::new(
            Some(salt), // Salt = Random[0..20]
            shared_secret.as_bytes()         // IKM = Shared Secret
        );
        let mut auth_key = [0u8; 32]; // Reality uses AES-256 (32 bytes key)
        if hk.expand(b"REALITY", &mut auth_key).is_err() { return false; }
        debug!("Reality Debug: auth_key: {}", hex::encode(auth_key));

        // 4. AEAD Decrypt (AES-256-GCM)
        let key = aes_gcm::Key::<aes_gcm::Aes256Gcm>::from_slice(&auth_key);
        let cipher = aes_gcm::Aes256Gcm::new(key);
        let nonce_bytes = &info.client_random[20..32];
        let nonce = Nonce::from_slice(nonce_bytes); // Nonce = Random[20..32] (12 bytes)
        debug!("Reality Debug: salt: {}, nonce: {}", hex::encode(salt), hex::encode(nonce_bytes));

        // 5. AAD Construction
        // AAD Strategy: Reality uses the Handshake message (excluding Record Header)
        // CRITICAL: Xray-core zeroes out the SessionID field (the ciphertext) in the AAD!
        let handshake_msg = if full_client_hello.len() > 5 && full_client_hello[0] == 0x16 { 
            &full_client_hello[5..] 
        } else { 
            full_client_hello 
        };

        let mut aad_buffer = handshake_msg.to_vec();
        
        // Robust search for session_id in AAD buffer
        let sid_hex = hex::encode(&info.session_id);
        let aad_hex = hex::encode(&aad_buffer);
        if let Some(pos_char) = aad_hex.find(&sid_hex) {
            let pos = pos_char / 2;
            debug!("Reality Debug: Found session_id in AAD at offset {}", pos);
            // Zero it
            for i in 0..32 {
                if pos + i < aad_buffer.len() {
                    aad_buffer[pos + i] = 0;
                }
            }
        } else {
            warn!("Reality verification failed: Could not find SessionID in handshake AAD buffer! Falling back to offset 39 guess.");
            // Fallback to offset 39 guess if not found (Type(1) + Len(3) + Ver(2) + Rnd(32) + SID_Len(1) = 39)
            if aad_buffer.len() >= 39 + 32 {
                for i in 0..32 { aad_buffer[39 + i] = 0; }
            }
        }
        debug!("Reality Debug: AAD buffer (after zeroing SID): {}", hex::encode(&aad_buffer));

        let mut buffer = info.session_id.clone();
        
        // Decrypt SessionID in-place using the zeroed-out AAD
        if cipher.decrypt_in_place(nonce, &aad_buffer, &mut buffer).is_err() {
            warn!("Reality verification failed: AEAD Decrypt error (Salt=20).");
            return false;
        }
        debug!("Reality Debug: Decrypted SessionID payload: {}", hex::encode(&buffer));

        // 6. Verify ShortId
        // Decrypted buffer structure can vary by client:
        // Case A (Standard): [Timestamp(4) | ShortId(8) | ...] -> Offset 4
        // Case B (Some uTLS): [Constant(4) | Timestamp(4) | ShortId(8) | ...] -> Offset 8
        if buffer.len() < 16 { 
            warn!("Reality verification failed: Decrypted payload too short ({})", buffer.len());
            return false; 
        }
        
        let sid_4 = &buffer[4..12];
        let sid_8 = &buffer[8..16];
        
        let mut found = false;
        for param_id in &self.reality_config.short_ids {
            if param_id == sid_4 || param_id == sid_8 {
                found = true;
                break;
            }
        }
        
        if !found {
            warn!("Reality verification failed: ShortId mismatch. Payload[4..12]: {}, Payload[8..16]: {}, Expected one of: {:?}", 
                hex::encode(sid_4),
                hex::encode(sid_8),
                self.reality_config.short_ids.iter().map(hex::encode).collect::<Vec<_>>()
            );
        } else {
            info!("Reality client verified successfully (ShortID matched)");
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
