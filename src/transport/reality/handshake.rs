use anyhow::{anyhow, Result};
use bytes::{BytesMut, BufMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info, warn, error};

use super::tls::{ClientHello, TlsRecord};
use super::{RealityAuth, RealityConfig, hello_parser};
use super::crypto::{RealityCrypto, TlsKeys};

#[derive(Clone)]
pub struct RealityHandshake {
    config: RealityConfig,
}

struct HandshakeTranscript {
    buffer: Vec<u8>,
}

impl HandshakeTranscript {
    fn new(client_hello: &[u8]) -> Self {
        Self { buffer: client_hello.to_vec() }
    }

    fn push(&mut self, msg: &[u8]) {
        self.buffer.extend_from_slice(msg);
    }

    fn hash(&self) -> Vec<u8> {
        let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
        ctx.update(&self.buffer);
        ctx.finish().as_ref().to_vec()
    }
}

impl RealityHandshake {
    pub fn new(config: RealityConfig) -> Self {
        Self { config }
    }

    /// Reality 握手with认证验证和回落
    /// Reality 握手with认证验证和回落
    pub async fn perform(&self, mut client_stream: TcpStream) -> Result<super::stream::TlsStream<TcpStream>> {
        // 1. 读取 ClientHello
        let mut buffer = BytesMut::with_capacity(2048);
        while buffer.len() < 5 {
            let n = client_stream.read_buf(&mut buffer).await?;
            if n == 0 { return Err(anyhow!("Connection closed early")); }
        }
        if buffer[0] != 0x16 {
            return self.fallback_to_dest(client_stream, &buffer).await;
        }
        let record_len = u16::from_be_bytes([buffer[3], buffer[4]]) as usize;
        while buffer.len() < 5 + record_len {
            let n = client_stream.read_buf(&mut buffer).await?;
            if n == 0 { return Err(anyhow!("Connection closed early")); }
        }

        let info = hello_parser::parse_client_hello(&buffer)?
            .ok_or_else(|| anyhow!("Not a valid ClientHello"))?;
        
        info!("ClientHello received, SNI: {:?}", info.server_name);
        
        // 2. 验证 Reality 认证
        debug!("Client SessionID: {}", hex::encode(info.session_id));
        debug!("Client Random: {}", hex::encode(info.client_random));
        
        let auth = RealityAuth::new(&self.config.private_key)?;
        let is_reality_client = auth.verify_client_auth(&info.client_random, info.session_id);
        
        debug!("Reality authentication result: {}", is_reality_client);
        
        if !is_reality_client {
            warn!("Reality authentication failed - falling back to dest");
            // 注意：fallback 需要去掉 TLS Record Header
            return self.fallback_to_dest(client_stream, &buffer[5..5+record_len]).await;
        }
        
        info!("✅ Reality authentication successful!");
        
        // 3. 执行 Reality 握手（使用我们自己的密钥）
        let client_key_share = info.public_key.ok_or_else(|| anyhow!("No X25519 key share"))?;

        let crypto = RealityCrypto::new();
        let my_public_key = crypto.get_public_key();
        let shared_secret = crypto.derive_shared_secret(client_key_share)?;

        // 4. 构造 ServerHello（带 Reality 认证）
        use rand::RngCore;
        let mut server_random = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut server_random);

        let mut server_hello = super::tls::ServerHello::new_reality(
            info.session_id,
            server_random,
            &my_public_key
        )?;
        
        server_hello.modify_for_reality(&self.config.private_key, &info.client_random)?;

        // 5. 发送 ServerHello 和 CCS
        client_stream.write_all(&server_hello.encode()).await?;
        client_stream.write_all(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]).await?;
        debug!("ServerHello & CCS sent");

        // 6. 推导握手密钥
        let client_hello_payload = &buffer[5..5+record_len];
        let mut transcript = HandshakeTranscript::new(client_hello_payload);
        transcript.push(server_hello.handshake_payload());
        
        let (hs_keys, handshake_secret) = TlsKeys::derive_handshake_keys(
            &shared_secret, 
            &transcript.hash()
        )?;
        
        // 7. 发送加密握手消息（标准 TLS 1.3：EE + Cert + Fin）
        let ee_msg = vec![8, 0, 0, 2, 0, 0];
        
        // Certificate 消息（空证书列表）
        let cert_msg = vec![
            11,       // Type: Certificate
            0, 0, 4,  // Length: 4 bytes
            0,        // Certificate Request Context Length: 0
            0, 0, 0   // Certificate List Length: 0
        ];
        
        transcript.push(&ee_msg);
        transcript.push(&cert_msg);
        
        let hash1 = transcript.hash();
        let verify_data = TlsKeys::calculate_verify_data(&hs_keys.server_traffic_secret, &hash1)?;
        
        let mut fin_msg = BytesMut::new();
        fin_msg.put_u8(20);
        let fin_len = verify_data.len() as u32;
        fin_msg.put_slice(&fin_len.to_be_bytes()[1..4]);
        fin_msg.put_slice(&verify_data);
        
        transcript.push(&fin_msg);
        
        // 打包所有消息到一个 TLS Record
        let mut bundle = BytesMut::new();
        bundle.put_slice(&ee_msg);
        bundle.put_slice(&cert_msg);
        bundle.put_slice(&fin_msg);
        
        let bundled_record = hs_keys.encrypt_server_record(0, &bundle, 22)?;
        client_stream.write_all(&bundled_record).await?;
        
        info!("Server handshake complete, waiting for client Finished...");

        // 8. 读取客户端 Finished
        let mut buf = BytesMut::with_capacity(4096);
        
        loop {
            if buf.len() < 5 {
                let n = client_stream.read_buf(&mut buf).await?;
                if n == 0 { return Err(anyhow!("Connection closed")); }
                if buf.len() < 5 { continue; }
            }
            
            let ctype = buf[0];
            let rlen = u16::from_be_bytes([buf[3], buf[4]]) as usize;
            
            if buf.len() < 5 + rlen {
                let n = client_stream.read_buf(&mut buf).await?;
                if n == 0 { return Err(anyhow!("EOF")); }
                continue;
            }
            
            let mut record_data = buf.split_to(5 + rlen);
            
            if ctype == 20 { continue; }
            
            if ctype == 23 {
                let mut header = [0u8; 5];
                header.copy_from_slice(&record_data[..5]);
                let (inner_type, plen) = hs_keys.decrypt_client_record(0, &header, &mut record_data[5..])?;
                
                if inner_type == 21 {
                    let level = if plen > 0 { record_data[5] } else { 0 };
                    let desc = if plen > 1 { record_data[6] } else { 0 };
                    error!("Client Alert: {}/{}", level, desc);
                    return Err(anyhow!("Client sent Alert {}/{}", level, desc));
                }
                
                if inner_type == 22 && plen > 0 && record_data[5] == 20 {
                    info!("✅ Client Finished received!");
                    break;
                }
            }
        }
        
        // 9. 推导应用层密钥
        let app_keys = TlsKeys::derive_application_keys(&handshake_secret, &transcript.hash())?;
        
        info!("🎉 Reality handshake successful! Tunnel established.");
        Ok(super::stream::TlsStream::new_with_buffer(client_stream, app_keys, buf))
    }
    
    /// 回落到真实的 dest 服务器（透明代理）
    async fn fallback_to_dest(&self, mut client: TcpStream, client_hello: &[u8]) -> Result<super::stream::TlsStream<TcpStream>> {
        info!("Falling back to dest: {}", self.config.dest);
        
        // 连接到 dest
        let mut dest = TcpStream::connect(&self.config.dest).await
            .map_err(|e| anyhow!("Failed to connect to dest: {}", e))?;
        
        // 构造完整的 ClientHello TLS Record
        let mut ch_record = BytesMut::new();
        ch_record.put_u8(0x16);
        ch_record.put_u16(0x0303);
        ch_record.put_u16(client_hello.len() as u16);
        ch_record.put_slice(client_hello);
        
        // 转发 ClientHello
        dest.write_all(&ch_record).await?;
        
        // 启动双向透明转发
        tokio::spawn(async move {
            let (mut client_read, mut client_write) = client.split();
            let (mut dest_read, mut dest_write) = dest.split();
            
            let c2d = tokio::io::copy(&mut client_read, &mut dest_write);
            let d2c = tokio::io::copy(&mut dest_read, &mut client_write);
            
            tokio::select! {
                _ = c2d => {},
                _ = d2c => {},
            }
        });
        
        // 返回错误，因为连接已经被转发
        Err(anyhow!("Connection fell back to dest"))
    }
}
