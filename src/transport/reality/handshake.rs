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

    pub async fn perform(&self, mut client_stream: TcpStream) -> Result<super::stream::TlsStream<TcpStream>> {
        // 1. 读取 ClientHello
        let (client_hello, client_hello_raw) = self.read_client_hello(&mut client_stream).await?;
        info!("ClientHello received, SNI: {:?}", client_hello.get_sni());
        debug!("ClientHello hex (first 100 bytes): {}", hex::encode(&client_hello_raw[..client_hello_raw.len().min(100)]));

        // 2. 提取 Client Key Share
        let client_key_share = match client_hello.get_key_share() {
            Some(key) => key,
            None => return Err(anyhow!("No X25519 key share")),
        };
        debug!("Client Key Share: {}", hex::encode(&client_key_share));

        // 3. 生成服务器密钥对
        let crypto = RealityCrypto::new();
        let my_public_key = crypto.get_public_key();
        let shared_secret = crypto.derive_shared_secret(&client_key_share)?;
        debug!("Server Public Key: {}", hex::encode(&my_public_key));
        debug!("Shared Secret: {}", hex::encode(&shared_secret));

        // 4. 构造 ServerHello（带 Reality 认证）
        use rand::RngCore;
        let mut server_random = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut server_random);
        debug!("Server Random (before Reality): {}", hex::encode(&server_random));

        let mut server_hello = super::tls::ServerHello::new_reality(
            &client_hello.session_id,
            server_random,
            &my_public_key
        )?;
        
        server_hello.modify_for_reality(&self.config.private_key, &client_hello.random)?;

        // 5. 发送 ServerHello 和 CCS
        let sh_bytes = server_hello.encode();
        debug!("ServerHello hex: {}", hex::encode(&sh_bytes));
        client_stream.write_all(&sh_bytes).await?;
        
        let ccs = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01];
        debug!("CCS hex: {}", hex::encode(&ccs));
        client_stream.write_all(&ccs).await?;
        info!("ServerHello & CCS sent");

        // 6. 推导握手密钥
        let transcript0 = vec![client_hello_raw.as_slice(), server_hello.handshake_payload()];
        let transcript0_hash = super::crypto::hash_transcript(&transcript0);
        debug!("Transcript Hash (CH+SH): {}", hex::encode(&transcript0_hash));
        
        let (mut hs_keys, handshake_secret) = TlsKeys::derive_handshake_keys(
            &shared_secret, 
            &transcript0_hash
        )?;
        debug!("Server Handshake Traffic Secret: {}", hex::encode(&hs_keys.server_traffic_secret));
        
        // 7. 构造并发送加密握手消息
        
        // EncryptedExtensions (空)
        let ee_msg = vec![8, 0, 0, 2, 0, 0];
        debug!("EncryptedExtensions plaintext: {}", hex::encode(&ee_msg));
        
        let ee_record = hs_keys.encrypt_server_record(0, &ee_msg, 22)?;
        debug!("EncryptedExtensions encrypted: {}", hex::encode(&ee_record));
        client_stream.write_all(&ee_record).await?;
        
        // Certificate (空) - RFC 8446: 如果证书列表为空，不发送 CertificateVerify
        let cert_msg = vec![11, 0, 0, 4, 0, 0, 0, 0];
        debug!("Certificate plaintext: {}", hex::encode(&cert_msg));
        
        let cert_record = hs_keys.encrypt_server_record(1, &cert_msg, 22)?;
        debug!("Certificate encrypted: {}", hex::encode(&cert_record));
        client_stream.write_all(&cert_record).await?;
        
        // Finished (直接在 Certificate 之后，跳过 CertificateVerify)
        let transcript1 = vec![
            client_hello_raw.as_slice(),
            server_hello.handshake_payload(),
            &ee_msg,
            &cert_msg
        ];
        let hash1 = super::crypto::hash_transcript(&transcript1);
        debug!("Transcript Hash (for Finished): {}", hex::encode(&hash1));
        
        let verify_data = TlsKeys::calculate_verify_data(&hs_keys.server_traffic_secret, &hash1)?;
        debug!("Verify Data: {}", hex::encode(&verify_data));
        
        let mut fin_msg = BytesMut::new();
        fin_msg.put_u8(20);
        let fin_len = verify_data.len() as u32;
        fin_msg.put_slice(&fin_len.to_be_bytes()[1..4]);
        fin_msg.put_slice(&verify_data);
        debug!("Finished plaintext: {}", hex::encode(&fin_msg));
        
        let fin_record = hs_keys.encrypt_server_record(2, &fin_msg, 22)?;
        debug!("Finished encrypted: {}", hex::encode(&fin_record));
        client_stream.write_all(&fin_record).await?;
        
        info!("All handshake messages sent, waiting for client response...");

        // 8. 读取客户端响应
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
            debug!("Client record received: {}", hex::encode(&record_data));
            
            if ctype == 20 { 
                debug!("Skipping CCS from client");
                continue;
            }
            
            if ctype == 23 {
                let mut header = [0u8; 5];
                header.copy_from_slice(&record_data[..5]);
                
                match hs_keys.decrypt_client_record(0, &header, &mut record_data[5..]) {
                    Ok((inner_type, plen)) => {
                        debug!("Decrypted client message: type={}, len={}", inner_type, plen);
                        debug!("Decrypted content: {}", hex::encode(&record_data[5..5+plen]));
                        
                        if inner_type == 21 {
                            let level = if plen > 0 { record_data[5] } else { 0 };
                            let desc = if plen > 1 { record_data[6] } else { 0 };
                            error!("❌ Client Alert: level={}, description={}", level, desc);
                            error!("Alert details: Level {} = {}, Description {} = {}", 
                                level, alert_level_name(level),
                                desc, alert_description_name(desc));
                            return Err(anyhow!("Client sent Alert {}/{}", level, desc));
                        }
                        
                        if inner_type == 22 && plen > 0 && record_data[5] == 20 {
                            info!("✅ Client Finished received!");
                            break;
                        }
                    }
                    Err(e) => {
                        error!("Failed to decrypt client record: {}", e);
                        return Err(e);
                    }
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

fn alert_level_name(level: u8) -> &'static str {
    match level {
        1 => "Warning",
        2 => "Fatal",
        _ => "Unknown"
    }
}

fn alert_description_name(desc: u8) -> &'static str {
    match desc {
        0 => "close_notify",
        10 => "unexpected_message",
        20 => "bad_record_mac",
        21 => "decryption_failed",
        22 => "record_overflow",
        40 => "handshake_failure",
        42 => "bad_certificate",
        43 => "unsupported_certificate",
        44 => "certificate_revoked",
        45 => "certificate_expired",
        46 => "certificate_unknown",
        47 => "illegal_parameter",
        48 => "unknown_ca",
        49 => "access_denied",
        50 => "decode_error",
        51 => "decrypt_error",
        80 => "internal_error",
        86 => "inappropriate_fallback",
        90 => "user_canceled",
        109 => "missing_extension",
        110 => "unsupported_extension",
        112 => "unrecognized_name",
        113 => "bad_certificate_status_response",
        116 => "certificate_required",
        120 => "no_application_protocol",
        _ => "unknown"
    }
}
