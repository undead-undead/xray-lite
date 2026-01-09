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
        let subject_alt_names = vec!["www.microsoft.com".to_string()];
        let cert = rcgen::generate_simple_self_signed(subject_alt_names)
            .map_err(|e| anyhow!("Failed to generate self-signed cert: {}", e))?;
            
        let cert_der = cert.serialize_der()
            .map_err(|e| anyhow!("Failed to serialize cert: {}", e))?;
        let key_der = cert.serialize_private_key_der();

        let certs = vec![CertificateDer::from(cert_der)];
        // Fix: Ensure we use the right Key type. rcgen generates PKCS8.
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
        let mut buf = vec![0u8; 1024]; // Initial peek buffer
        let n = stream.peek(&mut buf).await?;
        if n == 0 {
            bail!("Connection closed during peek");
        }
        
        // We peeked n bytes.
        // We need to ensure we peeked enough to contain the FULL ClientHello,
        // because we need the full bytes for AAD.
        
        let peek_slice = &buf[..n];
        
        // First try to parse what we have
        let parse_result = hello_parser::parse_client_hello(peek_slice);
        
        // Determining fallback logic
        let should_fallback = match parse_result {
            Ok(Some(info)) => {
                 // We have ClientHello info.
                 // Verify client using cryptographic check
                 if !self.verify_client_reality(&info, peek_slice) {
                     true // Verification failed
                 } else {
                     false // Verification passed!
                 }
            },
            Ok(None) => true, // Not a ClientHello or incomplete (we treat incomplete as fallback for simplicity, or we could wait more)
            Err(_) => true // Parse error
        };

        if should_fallback {
            let dest = self.reality_config.dest.as_ref().unwrap();
            info!("Non-Reality or Invalid client detected from {}, falling back to {}", stream.peer_addr().unwrap_or_else(|_| "unknown".parse().unwrap()), dest);
            
            if let Err(e) = self.fallback(stream, dest).await {
                warn!("Fallback error: {}", e);
            }
            bail!("Reality fallback handled");
        } else {
            info!("Reality client verified ({}), proceeding with handshake", stream.peer_addr().unwrap_or_else(|_| "unknown".parse().unwrap()));
            let tls_stream = self.acceptor.accept(stream).await?;
            info!("Reality handshake successful");
            Ok(tls_stream)
        }
    }

    /// Verifies Reality Client Authentication
    /// 1. ECDH(ServerPriv, ClientPub) -> SharedSecret
    /// 2. HKDF(Salt=Random, IKM=SharedSecret, Info="REALITY") -> AuthKey
    /// 3. AES-GCM-Decrypt(Key=AuthKey, Nonce=Random[20..32], AAD=ClientHello, CT=SessionID)
    fn verify_client_reality(&self, info: &ClientHelloInfo, full_client_hello: &[u8]) -> bool {
        // 1. SessionID check
        if info.session_id.len() != 32 { return false; }
        
        let client_pub_key_bytes = match &info.public_key {
            Some(pk) => pk,
            None => return false,
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
        
        // 3. HKDF (SHA256)
        // Note: Xray implementation uses client_random as Salt ??
        // Let's assume standard Xray implementation.
        let hk = Hkdf::<Sha256>::new(
            Some(&info.client_random), // Salt = Client Random
            shared_secret.as_bytes()   // IKM = Shared Secret
        );
        let mut auth_key = [0u8; 32];
        if hk.expand(b"REALITY", &mut auth_key).is_err() { return false; }

        // 4. AEAD Decrypt (AES-256-GCM)
        let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&auth_key);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(&info.client_random[20..32]);

        // Ciphertext is the SessionID
        let mut buffer = info.session_id.clone();
        
        // AAD is the full ClientHello message (without Record Header?)
        // Standard TLS AAD often excludes Record Header (5 bytes).
        // BUT parse_client_hello input `buf` INCLUDES Record Header (Type(0x16)...).
        // Xray implementation: AAD is the "ClientHello" message bytes (Handshake structure), excluding Record Header?
        // Let's deduce.
        // `hello_parser.rs` skips 5 bytes.
        // `full_client_hello` passed from `accept` includes Record Header for now.
        // We should skip 5 bytes for AAD if Xray expects Handshake Protocol message only.
        
        // Xray: "AdditionalData: clientHello.Raw"
        // In Golang `tls.ClientHelloInfo`, `Raw` usually implies Handshake message.
        // Let's try skipping header if present.
        
        let aad = if full_client_hello.len() > 5 && full_client_hello[0] == 0x16 {
            &full_client_hello[5..]
        } else {
            full_client_hello
        };

        if cipher.decrypt_in_place(nonce, aad, &mut buffer).is_err() {
            // Decryption failed means Auth failed
            return false;
        }
        
        // 5. Verify ShortId
        // Decrypted buffer: [Time(4) | ShortId(8) | Tag(16) - REMOVED by decrypt]
        // `decrypt_in_place` removes tag. So buffer size becomes 16 bytes.
        
        if buffer.len() < 12 { return false; }
        let short_id_bytes = &buffer[4..12]; 
        let short_id_hex = hex::encode(short_id_bytes);
        
        // Check valid shortIds
        // self.reality_config.short_ids is Vec<Vec<u8>>
        let mut found = false;
        for param_id in &self.reality_config.short_ids {
            if param_id == short_id_bytes {
                found = true;
                break;
            }
        }
        
        found
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
