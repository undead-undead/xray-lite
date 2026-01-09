use std::sync::Arc;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::net::TcpStream;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio_rustls::TlsAcceptor;
use rustls::ServerConfig;
use rustls::reality::RealityConfig;
use anyhow::{Result, anyhow, bail};
use tracing::{info, warn, error, debug};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use hkdf::Hkdf;
use sha2::Sha256;
use aes_gcm::{Aes256Gcm, KeyInit, AeadInPlace, Nonce};
use bytes::Buf;

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

        let base_reality_config = RealityConfig::new(private_key)
            .with_verify_client(true)
            .with_short_ids(short_ids_bytes)
            .with_dest(dest.unwrap_or_else(|| "www.microsoft.com:443".to_string()));

        base_reality_config.validate().map_err(|e| anyhow!("Reality config validation failed: {:?}", e))?;

        let dest_str = base_reality_config.dest.as_deref().unwrap_or("www.microsoft.com");
        let dest_host = dest_str.split(':').next().unwrap_or("www.microsoft.com");
        let subject_alt_names = vec![dest_host.to_string()];
        
        let cert = rcgen::generate_simple_self_signed(subject_alt_names)
            .map_err(|e| anyhow!("Failed to generate self-signed cert: {}", e))?;
        let cert_der = cert.serialize_der().map_err(|e| anyhow!("Failed to serialize cert: {}", e))?;
        let key_der = cert.serialize_private_key_der();
        let certs = vec![CertificateDer::from(cert_der)];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));

        let mut config = ServerConfig::builder().with_no_client_auth().with_single_cert(certs.clone(), key.clone_key())
            .map_err(|e| anyhow!("Failed to create ServerConfig: {}", e))?;
        config.reality_config = Some(Arc::new(base_reality_config.clone()));
        let acceptor = TlsAcceptor::from(Arc::new(config));

        Ok(Self { 
            acceptor,
            reality_config: Arc::new(base_reality_config),
        })
    }

    /// Accept a connection.
    pub async fn accept(&self, mut stream: TcpStream) -> Result<tokio_rustls::server::TlsStream<PrefixedStream<TcpStream>>> {
        let mut buffer = Vec::with_capacity(2048);
        while buffer.len() < 5 {
            let mut chunk = [0u8; 1024];
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                if buffer.is_empty() { bail!("Connection closed empty"); }
                break; 
            }
            buffer.extend_from_slice(&chunk[..n]);
        }

        let mut needed = buffer.len();
        if buffer.len() >= 5 && buffer[0] == 0x16 {
            let len = u16::from_be_bytes([buffer[3], buffer[4]]) as usize;
            needed = 5 + len;
        }

        let limit = 16384; 
        while buffer.len() < needed && buffer.len() < limit {
             let mut chunk = [0u8; 1024];
             let n = stream.read(&mut chunk).await?;
             if n == 0 { break; }
             buffer.extend_from_slice(&chunk[..n]);
        }

        let mut final_buffer = buffer;
        let parse_result = hello_parser::parse_client_hello(&final_buffer);

        if let Ok(Some(ref info)) = parse_result {
            if let Some(offset) = self.verify_client_reality(info, &final_buffer) {
                // Reality client verified!
                if offset == 8 {
                    debug!("Reality: Re-aligning offset 8 client to offset 4 for library compatibility");
                    if let Some(decrypted) = self.decrypt_session_id(info, &final_buffer) {
                        if decrypted.len() >= 16 {
                            // Struct: [Constant(4) | Timestamp(4) | ShortId(8)] -> 16 bytes
                            // Target: [Timestamp(4) | ShortId(8) | Constant(4)] -> 16 bytes
                            let mut new_plain = vec![0u8; 16];
                            new_plain[0..12].copy_from_slice(&decrypted[4..16]); // Copy [Timestamp|ShortID]
                            new_plain[12..16].copy_from_slice(&decrypted[0..4]);  // Copy Constant to tail
                            
                            if let Some(new_cipher) = self.encrypt_session_id(info, &final_buffer, &new_plain) {
                                let sid_hex = hex::encode(&info.session_id);
                                let buf_hex = hex::encode(&final_buffer);
                                if let Some(pos_char) = buf_hex.find(&sid_hex) {
                                    let pos = pos_char / 2;
                                    final_buffer[pos..pos+32].copy_from_slice(&new_cipher);
                                    debug!("Reality: Payload realigned successfully");
                                }
                            }
                        }
                    }
                }

                let prefixed = PrefixedStream::new(final_buffer, stream);
                let tls_stream = self.acceptor.accept(prefixed).await?;
                info!("Reality handshake successful");
                return Ok(tls_stream);
            }
        }

        // Fallback for non-reality
        let dest = self.reality_config.dest.as_deref().unwrap_or("www.microsoft.com:443");
        info!("Non-Reality client detected from {}, falling back...", stream.peer_addr().map(|a| a.to_string()).unwrap_or_default());
        self.fallback(stream, &final_buffer, dest).await?;
        bail!("Reality fallback handled");
    }

    /// Decrypts SessionID from ClientHello
    fn decrypt_session_id(&self, info: &ClientHelloInfo, full_client_hello: &[u8]) -> Option<Vec<u8>> {
        let client_pub_key_bytes = info.public_key.as_ref()?;
        let mut server_priv_bytes = [0u8; 32];
        server_priv_bytes.copy_from_slice(&self.reality_config.private_key);
        
        let client_pub_key_array: [u8; 32] = client_pub_key_bytes.as_slice().try_into().ok()?;
        let shared_secret = StaticSecret::from(server_priv_bytes).diffie_hellman(&X25519PublicKey::from(client_pub_key_array));
        
        let hk = Hkdf::<Sha256>::new(Some(&info.client_random[0..20]), shared_secret.as_bytes());
        let mut auth_key = [0u8; 32];
        hk.expand(b"REALITY", &mut auth_key).ok()?;

        let cipher = Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(&auth_key));
        let nonce = Nonce::from_slice(&info.client_random[20..32]);

        let handshake_msg = if full_client_hello.len() > 5 && full_client_hello[0] == 0x16 { &full_client_hello[5..] } else { full_client_hello };
        let mut aad_buffer = handshake_msg.to_vec();
        let sid_hex = hex::encode(&info.session_id);
        if let Some(pos_char) = hex::encode(&aad_buffer).find(&sid_hex) {
            let pos = pos_char / 2;
            for i in 0..32 { if pos + i < aad_buffer.len() { aad_buffer[pos + i] = 0; } }
        }

        let mut buffer = info.session_id.clone();
        cipher.decrypt_in_place(nonce, &aad_buffer, &mut buffer).ok()?;
        Some(buffer)
    }

    /// Encrypts SessionID for ClientHello
    fn encrypt_session_id(&self, info: &ClientHelloInfo, full_client_hello: &[u8], plaintext: &[u8]) -> Option<[u8; 32]> {
        let client_pub_key_bytes = info.public_key.as_ref()?;
        let mut server_priv_bytes = [0u8; 32];
        server_priv_bytes.copy_from_slice(&self.reality_config.private_key);

        let client_pub_key_array: [u8; 32] = client_pub_key_bytes.as_slice().try_into().ok()?;
        let shared_secret = StaticSecret::from(server_priv_bytes).diffie_hellman(&X25519PublicKey::from(client_pub_key_array));
        
        let hk = Hkdf::<Sha256>::new(Some(&info.client_random[0..20]), shared_secret.as_bytes());
        let mut auth_key = [0u8; 32];
        hk.expand(b"REALITY", &mut auth_key).ok()?;

        let cipher = Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(&auth_key));
        let nonce = Nonce::from_slice(&info.client_random[20..32]);

        let handshake_msg = if full_client_hello.len() > 5 && full_client_hello[0] == 0x16 { &full_client_hello[5..] } else { full_client_hello };
        let mut aad_buffer = handshake_msg.to_vec();
        let sid_hex = hex::encode(&info.session_id);
        if let Some(pos_char) = hex::encode(&aad_buffer).find(&sid_hex) {
            let pos = pos_char / 2;
            for i in 0..32 { if pos + i < aad_buffer.len() { aad_buffer[pos + i] = 0; } }
        }

        let mut buffer = plaintext.to_vec();
        while buffer.len() < 16 { buffer.push(0); }
        if buffer.len() > 16 { buffer.truncate(16); }
        
        cipher.encrypt_in_place(nonce, &aad_buffer, &mut buffer).ok()?;
        let mut res = [0u8; 32];
        res.copy_from_slice(&buffer);
        Some(res)
    }

    fn verify_client_reality(&self, info: &ClientHelloInfo, full_client_hello: &[u8]) -> Option<usize> {
        if info.session_id.len() != 32 { return None; }
        let client_pub_key_bytes = info.public_key.as_ref()?;
        if client_pub_key_bytes.len() != 32 { return None; }
        
        let mut server_priv_bytes = [0u8; 32];
        server_priv_bytes.copy_from_slice(&self.reality_config.private_key);
        
        let client_pub_array: [u8; 32] = client_pub_key_bytes.as_slice().try_into().ok()?;
        let shared_secret = StaticSecret::from(server_priv_bytes).diffie_hellman(&X25519PublicKey::from(client_pub_array));
        
        let salt = &info.client_random[0..20];
        let hk = Hkdf::<Sha256>::new(Some(salt), shared_secret.as_bytes());
        let mut auth_key = [0u8; 32];
        if hk.expand(b"REALITY", &mut auth_key).is_err() { return None; }

        let cipher = Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(&auth_key));
        let nonce = Nonce::from_slice(&info.client_random[20..32]);

        let handshake_msg = if full_client_hello.len() > 5 && full_client_hello[0] == 0x16 { &full_client_hello[5..] } else { full_client_hello };
        let mut aad_buffer = handshake_msg.to_vec();
        let sid_hex = hex::encode(&info.session_id);
        if let Some(pos_char) = hex::encode(&aad_buffer).find(&sid_hex) {
            let pos = pos_char / 2;
            for i in 0..32 { if pos + i < aad_buffer.len() { aad_buffer[pos + i] = 0; } }
        }

        let mut buffer = info.session_id.clone();
        if cipher.decrypt_in_place(nonce, &aad_buffer, &mut buffer).is_err() { return None; }

        if buffer.len() < 16 { return None; }
        let sid_4 = &buffer[4..12];
        let sid_8 = &buffer[8..16];
        
        for param_id in &self.reality_config.short_ids {
            if param_id == sid_8 { return Some(8); }
            if param_id == sid_4 { return Some(4); }
        }
        None
    }

    async fn fallback(&self, mut stream: TcpStream, prefix: &[u8], dest_addr: &str) -> Result<()> {
        let mut dest_stream = TcpStream::connect(dest_addr).await?;
        dest_stream.write_all(prefix).await?;
        tokio::io::copy_bidirectional(&mut stream, &mut dest_stream).await?;
        Ok(())
    }

    pub fn test_inject_auth(&self, server_random: &mut [u8; 32], client_random: &[u8; 32]) -> Result<()> {
        rustls::reality::inject_auth(server_random, &self.reality_config, client_random)
            .map_err(|e| anyhow!("Inject failure: {:?}", e))
    }
}

pub struct PrefixedStream<S> {
    prefix: std::io::Cursor<Vec<u8>>,
    inner: S,
}

impl<S> PrefixedStream<S> {
    pub fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix: std::io::Cursor::new(prefix),
            inner,
        }
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
