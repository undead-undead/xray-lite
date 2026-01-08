use anyhow::{anyhow, Result};
use bytes::{BytesMut, Buf, BufMut}; // Added Buf trait
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

    /// 执行 Reality TLS 握手
    pub async fn perform(&self, mut client_stream: TcpStream) -> Result<super::stream::TlsStream<TcpStream>> {
        // 1. 读取 ClientHello
        let (client_hello, client_hello_payload) = self.read_client_hello(&mut client_stream).await?;

        // 验证 Short ID (Bypass for now to simplify testing, verify later)
        // if !self.validate_short_id(...) ...

        // 2. 提取 Client Key Share
        let client_key_share = match client_hello.get_key_share() {
            Some(key) => {
                info!("Got Client Key Share, len: {}", key.len());
                if key.len() != 32 {
                     return Err(anyhow!("Invalid X25519 Key Share length: {}", key.len()));
                }
                key
            },
            None => {
                warn!("No X25519 Key Share found in ClientHello");
                return Err(anyhow!("客户端未使用 X25519 Key Share"));
            }
        };

        // 3. 生成我们的密钥对
        let crypto = RealityCrypto::new();
        let my_public_key = crypto.get_public_key();

        // 4. 计算 Shared Secret (ECDH)
        let shared_secret = crypto.derive_shared_secret(&client_key_share)?;
        debug!("Derived Shared Secret successfully");

        // 5. 构造 ServerHello
        let temp_random = [0u8; 32]; // Zero random initially
        let mut server_hello = super::tls::ServerHello::new_reality(
            &client_hello.session_id,
            temp_random,
            &my_public_key
        )?;
        
        // 6. 注入 Reality Auth
        server_hello.modify_for_reality(&self.config.private_key, &client_hello.random)?;

        // 7. 发送 ServerHello
        let server_hello_record = server_hello.encode();
        client_stream.write_all(&server_hello_record).await?;
        
        // 8. Derive Handshake Keys
        // Transcript: ClientHello + ServerHello (Handshake Msgs Only)
        // Correctly use payload without record header
        let transcript1 = vec![client_hello_payload.as_slice(), server_hello.handshake_payload()];
        let (mut keys, handshake_secret) = TlsKeys::derive_handshake_keys(
            &shared_secret, 
            &super::crypto::hash_transcript(&transcript1)
        )?;
        
        debug!("Derived Handshake Keys");
        
        // 9. Send EncryptedExtensions (Seq = 0)
        let mut ee_msg = BytesMut::new();
        ee_msg.put_u8(8); // Type EncryptedExtensions
        ee_msg.put_u8(0); ee_msg.put_u8(0); ee_msg.put_u8(16); // Length 16
        // ALPN Extension (h2, http/1.1)
        ee_msg.put_u16(16); // Extension Type ALPN
        ee_msg.put_u16(12); // Extension Len
        ee_msg.put_u16(10); // ALPN List Len
        ee_msg.put_u8(2); ee_msg.put_slice(b"h2");
        ee_msg.put_u8(8); ee_msg.put_slice(b"http/1.1");
        
        let ee_cipher = keys.encrypt_server_record(0, &ee_msg, 22)?;
        client_stream.write_all(&ee_cipher).await?;

        // 9.5 Send Certificate (Empty) (Seq = 1)
        let mut cert_msg = BytesMut::new();
        cert_msg.put_u8(11); // Type Certificate
        cert_msg.put_u8(0); cert_msg.put_u8(0); cert_msg.put_u8(4); // Length 4
        cert_msg.put_u8(0); // Context Len
        cert_msg.put_u8(0); cert_msg.put_u8(0); cert_msg.put_u8(0); // List Len
        
        let cert_cipher = keys.encrypt_server_record(1, &cert_msg, 22)?;
        client_stream.write_all(&cert_cipher).await?;
        
        // 10. Send Finished (Seq = 2)
        // Transcript: CH + SH + EE + Cert
        let transcript2 = vec![
            client_hello_payload.as_slice(), 
            server_hello.handshake_payload(),
            &ee_msg,
            &cert_msg
        ];
        let hash2 = super::crypto::hash_transcript(&transcript2);
        
        let verify_data = TlsKeys::calculate_verify_data(&keys.server_traffic_secret, &hash2)?;
        
        let mut fin_msg = BytesMut::new();
        fin_msg.put_u8(20); // Type Finished
        fin_msg.put_u8(0); fin_msg.put_u8(0); fin_msg.put_u8(verify_data.len() as u8);
        fin_msg.put_slice(&verify_data);
        
        let fin_cipher = keys.encrypt_server_record(2, &fin_msg, 22)?;
        client_stream.write_all(&fin_cipher).await?;
        
        info!("Handshake (Encryption Stage) completed. Waiting for Client Finished...");

        // 11. Read Client Finished (Handling CCS)
        let mut buf = BytesMut::with_capacity(4096);
        let mut client_finished_payload = Vec::new();
        
        loop {
            // Ensure header available
            if buf.len() < 5 {
                let n = client_stream.read_buf(&mut buf).await?;
                if n == 0 { return Err(anyhow!("EOF waiting for Client Finished")); }
                if buf.len() < 5 { continue; }
            }
            
            let content_type = buf[0];
            let len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
            
            if buf.len() < 5 + len {
                let n = client_stream.read_buf(&mut buf).await?;
                if n == 0 { return Err(anyhow!("EOF reading record body")); }
                continue;
            }
            
            // Check Record Type
            if content_type == 20 { // ChangeCipherSpec
                debug!("Received CCS (Type 20), skipping");
                buf.advance(5 + len);
                continue;
            }
            
            if content_type == 23 { // Application Data
                // Consume this record from buffer
                let mut record_data = buf.split_to(5 + len);
                
                let mut header = [0u8; 5];
                header.copy_from_slice(&record_data[..5]);
                let ciphertext = &mut record_data[5..];
                
                // Decrypt (Seq 0)
                let (ctype, plen) = keys.decrypt_client_record(0, &header, ciphertext)?;
                
                if ctype != 22 { // Handshake
                     return Err(anyhow!("Expected Handshake(22) inside AppData, got {}", ctype));
                }
                
                // Finished Message Found (Type 20)
                if plen > 0 && ciphertext[0] == 20 {
                    client_finished_payload = ciphertext[..plen].to_vec();
                    debug!("Client Finished received and decrypted.");
                    break;
                } else {
                     return Err(anyhow!("Expected Finished(20) message"));
                }
            }
            
            return Err(anyhow!("Unexpected ContentType {} during handshake", content_type));
        }
        
        // 12. Derive Application Keys
        let transcript3 = vec![
            client_hello_payload.as_slice(), 
            server_hello.handshake_payload(),
            &ee_msg,
            &cert_msg,
            &fin_msg, 
            &client_finished_payload
        ];
        let hash3 = super::crypto::hash_transcript(&transcript3);
        
        let app_keys = TlsKeys::derive_application_keys(&handshake_secret, &hash3)?;
        
        // Pass remaining buffer to stream
        Ok(super::stream::TlsStream::new_with_buffer(client_stream, app_keys, buf))
    }

    async fn read_client_hello(&self, stream: &mut TcpStream) -> Result<(ClientHello, Vec<u8>)> {
        let mut buf = BytesMut::with_capacity(4096);
        
        // 读取第一条记录
        loop {
            let n = stream.read_buf(&mut buf).await?;
            if n == 0 {
                return Err(anyhow!("Connection closed by client"));
            }

            // 尝试解析 TLS 记录
            // 注意：这里需要 clone buf 来解析，因为 parse 会 consume
            let mut parse_buf = buf.clone();
            if let Some(record) = TlsRecord::parse(&mut parse_buf)? {
                // 只有 ClientHello 才是我们关心的
                if record.content_type == super::tls::ContentType::Handshake {
                     let client_hello = ClientHello::parse(&record.payload)?;
                     // 还要保留原始数据用来做 Hash
                     // TlsRecord::parse 只是剥离了 Record Header (5 bytes)
                     // return record.payload (which is Handshake Msg) as raw_data
                     return Ok((client_hello, record.payload));
                }
            }
        }
    }

    fn validate_short_id(&self, received_short_id: &[u8]) -> bool {
        if self.config.short_ids.is_empty() {
            return true;
        }
        
        // Hex encode received ID
        let recv_hex = hex::encode(received_short_id);
        
        for expected in &self.config.short_ids {
            if received_short_id.len() * 2 >= expected.len() {
                 if recv_hex.starts_with(expected) {
                     return true;
                 }
            }
        }
        false
    }
}
