use anyhow::{anyhow, Result};
use bytes::{BytesMut, Buf, BufMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

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

    /// 执行 Reality TLS 握手 (v0.1.19: 独立记录发送模式)
    pub async fn perform(&self, mut client_stream: TcpStream) -> Result<super::stream::TlsStream<TcpStream>> {
        // 1. 读取 ClientHello
        let (client_hello, client_hello_payload) = self.read_client_hello(&mut client_stream).await?;
        debug!("ClientHello received (len: {})", client_hello_payload.len());

        // 2. 提取 Client Key Share
        let client_key_share = match client_hello.get_key_share() {
            Some(key) => key,
            None => return Err(anyhow!("客户端未使用 X25519 Key Share")),
        };

        // 3. 密钥交换
        let crypto = RealityCrypto::new();
        let my_public_key = crypto.get_public_key();
        let shared_secret = crypto.derive_shared_secret(&client_key_share)?;

        // 4. ServerHello
        use rand::RngCore;
        let mut server_random = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut server_random);

        let mut server_hello = super::tls::ServerHello::new_reality(
            &client_hello.session_id,
            server_random,
            &my_public_key
        )?;
        server_hello.modify_for_reality(&self.config.private_key, &client_hello.random)?;

        // 5. 发送 ServerHello & CCS
        client_stream.write_all(&server_hello.encode()).await?;
        client_stream.write_all(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]).await?;
        debug!("ServerHello & CCS sent");

        // 6. Derive Handshake Keys
        let transcript0 = vec![client_hello_payload.as_slice(), server_hello.handshake_payload()];
        let (mut hs_keys, handshake_secret) = TlsKeys::derive_handshake_keys(
            &shared_secret, 
            &super::crypto::hash_transcript(&transcript0)
        )?;
        
        // 7. 构造握手消息并独立发送 (Sequence Number: 0, 1, 2)
        
        // 7.1 EncryptedExtensions (EE)
        let mut extensions = BytesMut::new();
        // ALPN extension
        extensions.put_u16(16); // Type ALPN
        let mut alpn = BytesMut::new();
        alpn_val(&mut alpn, b"h2");
        // alpn_val(&mut alpn, b"http/1.1"); // Only h2 for robustness
        extensions.put_u16((alpn.len() + 2) as u16);
        extensions.put_u16(alpn.len() as u16);
        extensions.put_slice(&alpn);

        let mut ee_msg = BytesMut::new();
        ee_msg.put_u8(8); // Type EE
        let ee_body_len = (extensions.len() + 2) as u32;
        ee_msg.put_slice(&ee_body_len.to_be_bytes()[1..4]);
        ee_msg.put_u16(extensions.len() as u16);
        ee_msg.put_slice(&extensions);
        
        // 发送 EE (Record Seq 0)
        let ee_record = hs_keys.encrypt_server_record(0, &ee_msg, 22)?;
        client_stream.write_all(&ee_record).await?;
        
        // 7.2 Certificate (Cert) - Empty List
        let mut cert_msg = BytesMut::new();
        cert_msg.put_u8(11); // Type Certificate
        cert_msg.put_u8(0); cert_msg.put_u8(0); cert_msg.put_u8(4);
        cert_msg.put_u8(0); // Context Len
        cert_msg.put_u8(0); cert_msg.put_u8(0); cert_msg.put_u8(0); // List Len
        
        // 发送 Cert (Record Seq 1)
        let cert_record = hs_keys.encrypt_server_record(1, &cert_msg, 22)?;
        client_stream.write_all(&cert_record).await?;
        
        // 7.3 Finished (Fin)
        let transcript1 = vec![
            client_hello_payload.as_slice(), 
            server_hello.handshake_payload(),
            &ee_msg,
            &cert_msg
        ];
        let hash1 = super::crypto::hash_transcript(&transcript1);
        let verify_data = TlsKeys::calculate_verify_data(&hs_keys.server_traffic_secret, &hash1)?;
        
        let mut fin_msg = BytesMut::new();
        fin_msg.put_u8(20); // Type Finished
        let fin_len = verify_data.len() as u32;
        fin_msg.put_slice(&fin_len.to_be_bytes()[1..4]);
        fin_msg.put_slice(&verify_data);
        
        // 发送 Fin (Record Seq 2)
        let fin_record = hs_keys.encrypt_server_record(2, &fin_msg, 22)?;
        client_stream.write_all(&fin_record).await?;
        
        info!("Handshake (EE, Cert, Fin) sent separately. Waiting for client Finished...");

        // 8. 读取客户端响应 (SEQ=0)
        let mut buf = BytesMut::with_capacity(4096);
        let mut client_finished_payload = Vec::new();
        
        loop {
            if buf.len() < 5 {
                let n = client_stream.read_buf(&mut buf).await?;
                if n == 0 { return Err(anyhow!("Connection closed by client")); }
                if buf.len() < 5 { continue; }
            }
            let ctype = buf[0];
            let rlen = u16::from_be_bytes([buf[3], buf[4]]) as usize;
            if buf.len() < 5 + rlen {
                let n = client_stream.read_buf(&mut buf).await?;
                if n == 0 { return Err(anyhow!("EOF in handshake read")); }
                continue;
            }
            
            let mut record_data = buf.split_to(5 + rlen);
            if ctype == 20 { continue; } // Skip CCS
            if ctype == 23 {
                let mut header = [0u8; 5];
                header.copy_from_slice(&record_data[..5]);
                // Client starts at seq 0
                let (inner_type, plen) = hs_keys.decrypt_client_record(0, &header, &mut record_data[5..])?;
                
                if inner_type == 21 {
                    warn!("Client Alert decypted: {}/{}", record_data[5], record_data[6]);
                    return Err(anyhow!("Handshake failed: Client Alert {}/{}", record_data[5], record_data[6]));
                }
                if inner_type == 22 && record_data[5] == 20 {
                    client_finished_payload = record_data[5..5+plen].to_vec();
                    debug!("Client Finished received!");
                    break;
                }
            }
            return Err(anyhow!("Unexpected Record Type: {}", ctype));
        }
        
        // 9. 推导应用密钥
        let transcript_app = vec![
            client_hello_payload.as_slice(), 
            server_hello.handshake_payload(),
            &ee_msg,
            &cert_msg,
            &fin_msg
        ];
        let hash_app = super::crypto::hash_transcript(&transcript_app);
        let app_keys = TlsKeys::derive_application_keys(&handshake_secret, &hash_app)?;
        
        info!("Reality handshake successful! Tunnel established.");
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
}

fn alpn_val(buf: &mut BytesMut, name: &[u8]) {
    buf.put_u8(name.len() as u8);
    buf.put_slice(name);
}
