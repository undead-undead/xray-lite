use anyhow::{anyhow, Result};
use bytes::{BytesMut, Buf, BufMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info, warn, error};

use super::tls::{ClientHello, TlsRecord};
use super::RealityConfig;
use super::crypto::{RealityCrypto, TlsKeys};

#[derive(Clone)]
pub struct RealityHandshake {
    config: RealityConfig,
}

impl RealityHandshake {
    pub fn new(config: RealityConfig) -> Self {
        Self { config }
    }

    /// Reality 握手with认证验证和回落
    pub async fn perform(&self, mut client_stream: TcpStream) -> Result<super::stream::TlsStream<TcpStream>> {
        // 1. 读取 ClientHello
        let (client_hello, client_hello_raw) = self.read_client_hello(&mut client_stream).await?;
        info!("ClientHello received, SNI: {:?}", client_hello.get_sni());
        
        // 2. 验证 Reality 认证
        debug!("Client SessionID: {}", hex::encode(&client_hello.session_id));
        debug!("Client Random: {}", hex::encode(&client_hello.random));
        
        let auth = super::auth::RealityAuth::new(&self.config.private_key)?;
        let is_reality_client = auth.verify_client_auth(&client_hello.random, &client_hello.session_id);
        
        debug!("Reality authentication result: {}", is_reality_client);
        
        if !is_reality_client {
            warn!("Reality authentication failed - falling back to dest");
            return self.fallback_to_dest(client_stream, &client_hello_raw).await;
        }
        
        info!("✅ Reality authentication successful!");
        
        // 3. 执行 Reality 握手（使用我们自己的密钥）
        let client_key_share = match client_hello.get_key_share() {
            Some(key) => key,
            None => return Err(anyhow!("No X25519 key share")),
        };

        let crypto = RealityCrypto::new();
        let my_public_key = crypto.get_public_key();
        let shared_secret = crypto.derive_shared_secret(&client_key_share)?;

        // 4. 构造 ServerHello（带 Reality 认证）
        use rand::RngCore;
        let mut server_random = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut server_random);

        let mut server_hello = super::tls::ServerHello::new_reality(
            &client_hello.session_id,
            server_random,
            &my_public_key
        )?;
        
        server_hello.modify_for_reality(&self.config.private_key, &client_hello.random)?;

        // 5. 发送 ServerHello 和 CCS
        client_stream.write_all(&server_hello.encode()).await?;
        client_stream.write_all(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]).await?;
        debug!("ServerHello & CCS sent");

        // 6. 推导握手密钥
        let transcript0 = vec![client_hello_raw.as_slice(), server_hello.handshake_payload()];
        let (mut hs_keys, handshake_secret) = TlsKeys::derive_handshake_keys(
            &shared_secret, 
            &super::crypto::hash_transcript(&transcript0)
        )?;
        
        // 7. 发送加密握手消息（简化版：EE + Cert(empty) + Fin）
        let ee_msg = vec![8, 0, 0, 2, 0, 0];
        let cert_msg = vec![11, 0, 0, 4, 0, 0, 0, 0];
        
        let transcript1 = vec![
            client_hello_raw.as_slice(),
            server_hello.handshake_payload(),
            &ee_msg,
            &cert_msg
        ];
        let hash1 = super::crypto::hash_transcript(&transcript1);
        let verify_data = TlsKeys::calculate_verify_data(&hs_keys.server_traffic_secret, &hash1)?;
        
        let mut fin_msg = BytesMut::new();
        fin_msg.put_u8(20);
        let fin_len = verify_data.len() as u32;
        fin_msg.put_slice(&fin_len.to_be_bytes()[1..4]);
        fin_msg.put_slice(&verify_data);
        
        // 发送加密消息
        let ee_record = hs_keys.encrypt_server_record(0, &ee_msg, 22)?;
        client_stream.write_all(&ee_record).await?;
        
        let cert_record = hs_keys.encrypt_server_record(1, &cert_msg, 22)?;
        client_stream.write_all(&cert_record).await?;
        
        let fin_record = hs_keys.encrypt_server_record(2, &fin_msg, 22)?;
        client_stream.write_all(&fin_record).await?;
        
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
        let transcript_app = vec![
            client_hello_raw.as_slice(),
            server_hello.handshake_payload(),
            &ee_msg,
            &cert_msg,
            &fin_msg
        ];
        let app_keys = TlsKeys::derive_application_keys(&handshake_secret, &super::crypto::hash_transcript(&transcript_app))?;
        
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

    async fn read_client_hello(&self, stream: &mut TcpStream) -> Result<(ClientHello, Vec<u8>)> {
        let mut buf = BytesMut::with_capacity(4096);
        loop {
            let n = stream.read_buf(&mut buf).await?;
            if n == 0 { return Err(anyhow!("EOF reading CH")); }
            let mut parse_buf = buf.clone();
            if let Some(record) = TlsRecord::parse(&mut parse_buf)? {
                if record.content_type == super::tls::ContentType::Handshake {
                     let ch = ClientHello::parse(&record.payload)?;
                     return Ok((ch, record.payload));
                }
            }
        }
    }
}
