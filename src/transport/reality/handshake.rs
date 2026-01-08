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

    /// Reality 完整实现：证书转发模式
    pub async fn perform(&self, mut client_stream: TcpStream) -> Result<super::stream::TlsStream<TcpStream>> {
        // 1. 读取客户端的 ClientHello
        let (client_hello, client_hello_raw) = self.read_client_hello(&mut client_stream).await?;
        info!("ClientHello received from client, SNI: {:?}", client_hello.get_sni());

        // 2. 提取客户端的 Key Share（用于我们自己的加密）
        let client_key_share = match client_hello.get_key_share() {
            Some(key) => key,
            None => return Err(anyhow!("No X25519 key share from client")),
        };

        // 3. 连接到真实的 dest 服务器
        debug!("Connecting to dest: {}", self.config.dest);
        let mut dest_stream = TcpStream::connect(&self.config.dest).await
            .map_err(|e| anyhow!("Failed to connect to dest {}: {}", self.config.dest, e))?;
        
        // 4. 将 ClientHello 转发到 dest（完整的 TLS Record）
        let mut ch_record = BytesMut::new();
        ch_record.put_u8(0x16); // Handshake
        ch_record.put_u16(0x0303); // TLS 1.2
        ch_record.put_u16(client_hello_raw.len() as u16);
        ch_record.put_slice(&client_hello_raw);
        
        dest_stream.write_all(&ch_record).await?;
        debug!("Forwarded ClientHello to dest");

        // 5. 从 dest 读取 ServerHello
        let dest_server_hello_record = self.read_tls_record(&mut dest_stream).await?;
        
        if dest_server_hello_record.len() < 5 || dest_server_hello_record[0] != 0x16 {
            return Err(anyhow!("Invalid ServerHello from dest"));
        }
        
        let dest_sh_payload = &dest_server_hello_record[5..];
        debug!("Received ServerHello from dest, len={}", dest_sh_payload.len());

        // 6. 生成我们自己的密钥对
        let crypto = RealityCrypto::new();
        let my_public_key = crypto.get_public_key();
        let shared_secret = crypto.derive_shared_secret(&client_key_share)?;

        // 7. 构造我们自己的 ServerHello（带 Reality 认证）
        use rand::RngCore;
        let mut server_random = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut server_random);

        let mut server_hello = super::tls::ServerHello::new_reality(
            &client_hello.session_id,
            server_random,
            &my_public_key
        )?;
        
        // 注入 Reality 认证
        server_hello.modify_for_reality(&self.config.private_key, &client_hello.random)?;

        // 8. 发送我们的 ServerHello 和 CCS 给客户端
        client_stream.write_all(&server_hello.encode()).await?;
        client_stream.write_all(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]).await?;
        debug!("Sent modified ServerHello & CCS to client");

        // 9. 推导握手密钥
        let transcript0 = vec![client_hello_raw.as_slice(), server_hello.handshake_payload()];
        let (mut hs_keys, handshake_secret) = TlsKeys::derive_handshake_keys(
            &shared_secret, 
            &super::crypto::hash_transcript(&transcript0)
        )?;

        // 10. 从 dest 读取后续的握手消息（可能是 CCS + 加密握手消息）
        // 读取并丢弃 dest 的 CCS
        let _ = self.read_tls_record(&mut dest_stream).await;
        
        // 读取 dest 的加密握手消息（EncryptedExtensions, Certificate, CertificateVerify, Finished）
        // 我们不解密这些消息，而是构造自己的
        let _ = self.read_tls_record(&mut dest_stream).await;
        
        // 关闭与 dest 的连接
        drop(dest_stream);
        debug!("Closed connection to dest");

        // 11. 发送我们自己的加密握手消息
        // 使用简化的握手：EncryptedExtensions + Finished（无证书）
        
        let ee_msg = vec![8, 0, 0, 2, 0, 0]; // Type: EE, Len: 2, ExtLen: 0
        
        // Transcript: CH + SH + EE
        let transcript1 = vec![
            client_hello_raw.as_slice(),
            server_hello.handshake_payload(),
            &ee_msg
        ];
        let hash1 = super::crypto::hash_transcript(&transcript1);
        let verify_data = TlsKeys::calculate_verify_data(&hs_keys.server_traffic_secret, &hash1)?;
        
        let mut fin_msg = BytesMut::new();
        fin_msg.put_u8(20); // Type: Finished
        let fin_len_bytes = (verify_data.len() as u32).to_be_bytes();
        fin_msg.put_slice(&fin_len_bytes[1..4]);
        fin_msg.put_slice(&verify_data);
        
        // 打包发送 EE + Fin
        let mut bundle = BytesMut::new();
        bundle.put_slice(&ee_msg);
        bundle.put_slice(&fin_msg);
        
        let record = hs_keys.encrypt_server_record(0, &bundle, 22)?;
        client_stream.write_all(&record).await?;
        debug!("Sent EncryptedExtensions + Finished to client");
        
        info!("Server handshake complete, waiting for client Finished...");

        // 12. 读取客户端的 Finished
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
            
            if ctype == 20 { continue; } // Skip CCS
            
            if ctype == 23 {
                let mut header = [0u8; 5];
                header.copy_from_slice(&record_data[..5]);
                let (inner_type, plen) = hs_keys.decrypt_client_record(0, &header, &mut record_data[5..])?;
                
                if inner_type == 21 {
                    let level = if plen > 0 { record_data[5] } else { 0 };
                    let desc = if plen > 1 { record_data[6] } else { 0 };
                    error!("Client Alert: level={}, description={}", level, desc);
                    return Err(anyhow!("Client sent Alert {}/{}", level, desc));
                }
                
                if inner_type == 22 && plen > 0 && record_data[5] == 20 {
                    info!("Client Finished received!");
                    break;
                }
            }
        }
        
        // 13. 推导应用层密钥
        let transcript_app = vec![
            client_hello_raw.as_slice(),
            server_hello.handshake_payload(),
            &ee_msg,
            &fin_msg
        ];
        let app_keys = TlsKeys::derive_application_keys(&handshake_secret, &super::crypto::hash_transcript(&transcript_app))?;
        
        info!("🎉 Reality handshake successful! Tunnel established.");
        Ok(super::stream::TlsStream::new_with_buffer(client_stream, app_keys, buf))
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

    async fn read_tls_record(&self, stream: &mut TcpStream) -> Result<Vec<u8>> {
        let mut header = [0u8; 5];
        stream.read_exact(&mut header).await?;
        
        let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        let mut payload = vec![0u8; record_len];
        stream.read_exact(&mut payload).await?;
        
        let mut record = Vec::with_capacity(5 + record_len);
        record.extend_from_slice(&header);
        record.extend_from_slice(&payload);
        
        Ok(record)
    }
}
