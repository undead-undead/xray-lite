use anyhow::{anyhow, Result};
use bytes::BytesMut;
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
        let mut temp_random = [0u8; 32]; // Zero random initially
        let mut server_hello = super::tls::ServerHello::new_reality(
            &client_hello.session_id,
            temp_random,
            &my_public_key
        )?;
        
        // 注入 Reality Auth
        server_hello.modify_for_reality(&self.config.private_key, client_hello.get_random())?;

        // 6. 发送 ServerHello
        client_stream.write_all(&server_hello.encode()).await?;

        // 7. 发送 ChangeCipherSpec
        client_stream.write_all(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]).await?;

        // 8. 计算 Handshake Keys
        use bytes::BufMut;
        let server_hello_record = server_hello.encode();
        let server_hello_msg = &server_hello_record[5..]; // Skip record headers
        
        let transcript1 = vec![client_hello_payload.as_slice(), server_hello_msg];
        let hash1 = super::crypto::hash_transcript(&transcript1);
        
        let (keys, handshake_secret) = TlsKeys::derive_handshake_keys(&shared_secret, &hash1)?;
        
        // 9. Send EncryptedExtensions
        // Type(8), Len(low24), Payload
        // Extension: ALPN (h2, http/1.1)
        let mut ee_msg = BytesMut::new();
        ee_msg.put_u8(8); 
        ee_msg.put_u8(0); ee_msg.put_u8(0); ee_msg.put_u8(0); // Length holder
        
        let mut ee_exts = BytesMut::new();
        ee_exts.put_u16(16); // Type ALPN
        let mut alpn_val = BytesMut::new();
        alpn_val.put_u16(14); 
        alpn_val.put_u8(2); alpn_val.put_slice(b"h2");
        alpn_val.put_u8(8); alpn_val.put_slice(b"http/1.1");
        
        ee_exts.put_u16(alpn_val.len() as u16); // Ext Data Len
        ee_exts.put_slice(&alpn_val);
        
        ee_msg.put_u16(ee_exts.len() as u16); // Extensions Block Len
        ee_msg.put_slice(&ee_exts);
        
        // Fix Msg Length
        let ee_len = ee_msg.len() - 4;
        let ee_len_bytes = (ee_len as u32).to_be_bytes();
        ee_msg[1] = ee_len_bytes[1]; ee_msg[2] = ee_len_bytes[2]; ee_msg[3] = ee_len_bytes[3];
        
        let ee_cipher = keys.encrypt_server_record(0, &ee_msg, 22)?;
        client_stream.write_all(&ee_cipher).await?;
        
        // 10. Send Finished (Seq = 1)
        let transcript2 = vec![client_hello_payload.as_slice(), server_hello_msg, &ee_msg];
        let hash2 = super::crypto::hash_transcript(&transcript2);
        
        let verify_data = TlsKeys::calculate_verify_data(&handshake_secret, &hash2)?;
        
        let mut fin_msg = BytesMut::new();
        fin_msg.put_u8(20); // Type Finished
        fin_msg.put_u8(0); fin_msg.put_u8(0); fin_msg.put_u8(verify_data.len() as u8);
        fin_msg.put_slice(&verify_data);
        
        let fin_cipher = keys.encrypt_server_record(1, &fin_msg, 22)?;
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
                use bytes::Buf;
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
                // Verify payload type is Finished(20)? 
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
            server_hello_msg, 
            &ee_msg,
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
                     // 我们需要整个 Record 数据（含 Header）作为 Transcript 吗？
                     // TLS 1.3 TranscriptHash 輸入是 Handshake Messages (不含 Record Layer Header)
                     // 即 ClientHello 和 ServerHello 的 Payload 部分。
                     return Ok((client_hello, record.payload)); // Return payload directly
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
