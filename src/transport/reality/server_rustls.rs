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

pub struct RealityServerRustls {
    reality_config: Arc<RealityConfig>,
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
}

impl Clone for RealityServerRustls {
    fn clone(&self) -> Self {
        Self {
            reality_config: Arc::clone(&self.reality_config),
            certs: self.certs.clone(),
            key: match &self.key {
                PrivateKeyDer::Pkcs8(p) => PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(p.secret_pkcs8_der().to_vec())),
                _ => panic!("Unsupported key type"),
            },
        }
    }
}

impl RealityServerRustls {
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

        reality_config.validate().map_err(|e| anyhow!("Reality config validation failed: {:?}", e))?;

        let dest_str = reality_config.dest.as_deref().unwrap_or("www.microsoft.com");
        let dest_host = dest_str.split(':').next().unwrap_or("www.microsoft.com");
        let cert = rcgen::generate_simple_self_signed(vec![dest_host.to_string()])
            .map_err(|e| anyhow!("Failed to generate self-signed cert: {}", e))?;
        
        let certs = vec![CertificateDer::from(cert.serialize_der().map_err(|e| anyhow!("Cert serialization fail: {}", e))?)];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.serialize_private_key_der()));

        Ok(Self { 
            reality_config: Arc::new(reality_config),
            certs,
            key,
        })
    }

    pub async fn accept(&self, mut stream: TcpStream) -> Result<tokio_rustls::server::TlsStream<PrefixedStream<TcpStream>>> {
        let mut buffer = Vec::with_capacity(2048);
        while buffer.len() < 5 {
            let mut chunk = [0u8; 1024];
            let n = stream.read(&mut chunk).await?;
            if n == 0 { bail!("Connection closed early"); }
            buffer.extend_from_slice(&chunk[..n]);
        }

        let needed = if buffer[0] == 0x16 { 5 + u16::from_be_bytes([buffer[3], buffer[4]]) as usize } else { buffer.len() };
        while buffer.len() < needed && buffer.len() < 16384 {
             let mut chunk = [0u8; 1024];
             let n = stream.read(&mut chunk).await?;
             if n == 0 { break; }
             buffer.extend_from_slice(&chunk[..n]);
        }

        if let Ok(Some(info)) = hello_parser::parse_client_hello(&buffer) {
            if let Some((offset, auth_key)) = self.verify_client_reality(&info, &buffer) {
                info!("Reality: Verified client (Offset {}), using session AuthKey for ServerHello signature", offset);
                
                let mut conn_reality_config = (*self.reality_config).clone();
                conn_reality_config.private_key = auth_key.to_vec();
                conn_reality_config.verify_client = false; 

                let mut config = ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(self.certs.clone(), self.key.clone_key())
                    .map_err(|e| anyhow!("Config build fail: {}", e))?;
                config.reality_config = Some(Arc::new(conn_reality_config));

                let acceptor = TlsAcceptor::from(Arc::new(config));
                let prefixed = PrefixedStream::new(buffer, stream);
                
                match acceptor.accept(prefixed).await {
                    Ok(tls) => {
                        info!("Reality handshake successful");
                        return Ok(tls);
                    }
                    Err(e) => {
                        error!("Reality TLS handshake failed: {}", e);
                        bail!("Handshake failure");
                    }
                }
            }
        }

        let dest = self.reality_config.dest.as_deref().unwrap_or("www.microsoft.com:443");
        info!("Non-Reality client, falling back to {}", dest);
        self.fallback(stream, &buffer, dest).await?;
        bail!("Fallback total");
    }

    fn verify_client_reality(&self, info: &ClientHelloInfo, full_hello: &[u8]) -> Option<(usize, [u8; 32])> {
        if info.session_id.len() != 32 || info.public_key.is_none() { return None; }
        
        let mut server_priv = [0u8; 32];
        server_priv.copy_from_slice(&self.reality_config.private_key);
        let client_pub: [u8; 32] = info.public_key.as_ref()?.as_slice().try_into().ok()?;
        
        let shared = StaticSecret::from(server_priv).diffie_hellman(&X25519PublicKey::from(client_pub));
        let hk = Hkdf::<Sha256>::new(Some(&info.client_random[0..20]), shared.as_bytes());
        let mut auth_key = [0u8; 32];
        if hk.expand(b"REALITY", &mut auth_key).is_err() { return None; }

        let cipher = Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(&auth_key));
        let nonce = Nonce::from_slice(&info.client_random[20..32]);

        let handshake_msg = if full_hello[0] == 0x16 { &full_hello[5..] } else { full_hello };
        let mut aad = handshake_msg.to_vec();
        if let Some(pos) = hex::encode(&aad).find(&hex::encode(&info.session_id)).map(|p| p/2) {
            for i in 0..32 { if pos + i < aad.len() { aad[pos + i] = 0; } }
        }

        let mut buf = info.session_id.clone();
        if cipher.decrypt_in_place(nonce, &aad, &mut buf).is_err() { return None; }
        if buf.len() < 16 { return None; }

        for sid in &self.reality_config.short_ids {
            if sid == &buf[4..12] { return Some((4, auth_key)); }
            if sid == &buf[8..16] { return Some((8, auth_key)); }
        }
        None
    }

    async fn fallback(&self, mut stream: TcpStream, prefix: &[u8], dest: &str) -> Result<()> {
        let mut dest_stream = TcpStream::connect(dest).await?;
        dest_stream.write_all(prefix).await?;
        tokio::io::copy_bidirectional(&mut stream, &mut dest_stream).await?;
        Ok(())
    }
}

pub struct PrefixedStream<S> { prefix: std::io::Cursor<Vec<u8>>, inner: S }
impl<S> PrefixedStream<S> { pub fn new(prefix: Vec<u8>, inner: S) -> Self { Self { prefix: std::io::Cursor::new(prefix), inner } } }
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
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> { Pin::new(&mut self.inner).poll_write(cx, buf) }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> { Pin::new(&mut self.inner).poll_flush(cx) }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> { Pin::new(&mut self.inner).poll_shutdown(cx) }
}
