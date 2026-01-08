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

    /// 完整的 TLS 1.3 握手实现（带 Reality 认证）
    pub async fn perform(&self, mut client_stream: TcpStream) -> Result<super::stream::TlsStream<TcpStream>> {
        // 1. 读取 ClientHello
        let (client_hello, client_hello_raw) = self.read_client_hello(&mut client_stream).await?;
        info!("ClientHello received, SNI: {:?}", client_hello.get_sni());

        // 2. 提取 Client Key Share
        let client_key_share = match client_hello.get_key_share() {
            Some(key) => key,
            None => return Err(anyhow!("No X25519 key share")),
        };

        // 3. 生成服务器密钥对
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
        
        // 注入 Reality 认证
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
        
        // 7. 生成真实的自签名证书
        let (cert_msg, cert_key) = self.generate_certificate_message()?;
        
        // 8. 构造 EncryptedExtensions
        let ee_msg = self.build_encrypted_extensions();
        
        // 9. 构造 CertificateVerify（使用真实的签名）
        let transcript_cv = vec![
            client_hello_raw.as_slice(),
            server_hello.handshake_payload(),
            &ee_msg,
            &cert_msg
        ];
        let hash_cv = super::crypto::hash_transcript(&transcript_cv);
        let cv_msg = self.build_certificate_verify(&hash_cv, &cert_key)?;
        
        // 10. 构造 Finished
        let transcript_fin = vec![
            client_hello_raw.as_slice(),
            server_hello.handshake_payload(),
            &ee_msg,
            &cert_msg,
            &cv_msg
        ];
        let hash_fin = super::crypto::hash_transcript(&transcript_fin);
        let verify_data = TlsKeys::calculate_verify_data(&hs_keys.server_traffic_secret, &hash_fin)?;
        
        let mut fin_msg = BytesMut::new();
        fin_msg.put_u8(20); // Type: Finished
        let fin_len = verify_data.len() as u32;
        fin_msg.put_slice(&fin_len.to_be_bytes()[1..4]);
        fin_msg.put_slice(&verify_data);
        
        // 11. 发送所有加密握手消息（分别发送）
        let ee_record = hs_keys.encrypt_server_record(0, &ee_msg, 22)?;
        client_stream.write_all(&ee_record).await?;
        debug!("EncryptedExtensions sent (seq=0)");
        
        let cert_record = hs_keys.encrypt_server_record(1, &cert_msg, 22)?;
        client_stream.write_all(&cert_record).await?;
        debug!("Certificate sent (seq=1)");
        
        let cv_record = hs_keys.encrypt_server_record(2, &cv_msg, 22)?;
        client_stream.write_all(&cv_record).await?;
        debug!("CertificateVerify sent (seq=2)");
        
        let fin_record = hs_keys.encrypt_server_record(3, &fin_msg, 22)?;
        client_stream.write_all(&fin_record).await?;
        debug!("Finished sent (seq=3)");
        
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
            &cert_msg,
            &cv_msg,
            &fin_msg
        ];
        let app_keys = TlsKeys::derive_application_keys(&handshake_secret, &super::crypto::hash_transcript(&transcript_app))?;
        
        info!("🎉 Reality handshake successful! Tunnel established.");
        Ok(super::stream::TlsStream::new_with_buffer(client_stream, app_keys, buf))
    }

    fn build_encrypted_extensions(&self) -> Vec<u8> {
        vec![8, 0, 0, 2, 0, 0] // Type: EE, Len: 2, ExtLen: 0
    }

    fn generate_certificate_message(&self) -> Result<(Vec<u8>, rcgen::Certificate)> {
        use rcgen::{Certificate, CertificateParams, DistinguishedName};
        
        let mut params = CertificateParams::new(vec!["localhost".to_string()]);
        let mut dn = DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, "Reality Server");
        params.distinguished_name = dn;
        
        let cert = Certificate::from_params(params)
            .map_err(|e| anyhow!("Failed to generate certificate: {}", e))?;
        
        let cert_der = cert.serialize_der()
            .map_err(|e| anyhow!("Failed to serialize certificate: {}", e))?;
        
        // 构造 Certificate 握手消息
        let mut msg = BytesMut::new();
        msg.put_u8(11); // Type: Certificate
        
        // 消息体
        let mut body = BytesMut::new();
        body.put_u8(0); // Certificate Request Context (empty)
        
        // Certificate List
        let cert_list_len = 3 + cert_der.len() + 2; // cert_len(3) + cert + ext_len(2)
        body.put_u8(((cert_list_len >> 16) & 0xFF) as u8);
        body.put_u8(((cert_list_len >> 8) & 0xFF) as u8);
        body.put_u8((cert_list_len & 0xFF) as u8);
        
        // Single Certificate Entry
        body.put_u8(((cert_der.len() >> 16) & 0xFF) as u8);
        body.put_u8(((cert_der.len() >> 8) & 0xFF) as u8);
        body.put_u8((cert_der.len() & 0xFF) as u8);
        body.put_slice(&cert_der);
        body.put_u16(0); // Extensions (empty)
        
        // 消息长度
        let body_len = body.len() as u32;
        msg.put_slice(&body_len.to_be_bytes()[1..4]);
        msg.put_slice(&body);
        
        Ok((msg.to_vec(), cert))
    }

    fn build_certificate_verify(&self, transcript_hash: &[u8], cert: &rcgen::Certificate) -> Result<Vec<u8>> {
        use sha2::{Sha256, Digest};
        
        // 构造签名内容（TLS 1.3 格式）
        let mut content = Vec::new();
        content.extend_from_slice(&[0x20u8; 64]); // 64 个空格
        content.extend_from_slice(b"TLS 1.3, server CertificateVerify");
        content.push(0x00);
        content.extend_from_slice(transcript_hash);
        
        // 计算内容的 SHA256 哈希
        let mut hasher = Sha256::new();
        hasher.update(&content);
        let hash = hasher.finalize();
        
        // 使用 ring 进行 ECDSA 签名
        use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
        use ring::rand::SystemRandom;
        
        let rng = SystemRandom::new();
        
        // 从证书获取私钥 DER
        let key_der = cert.serialize_private_key_der();
        
        let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &key_der, &rng)
            .map_err(|e| anyhow!("Failed to parse key: {:?}", e))?;
        
        let signature = key_pair.sign(&rng, &hash)
            .map_err(|e| anyhow!("Failed to sign: {:?}", e))?;
        
        let mut msg = BytesMut::new();
        msg.put_u8(15); // Type: CertificateVerify
        
        let body_len = 2 + 2 + signature.as_ref().len();
        msg.put_slice(&(body_len as u32).to_be_bytes()[1..4]);
        msg.put_u16(0x0403); // Algorithm: ecdsa_secp256r1_sha256
        msg.put_u16(signature.as_ref().len() as u16);
        msg.put_slice(signature.as_ref());
        
        Ok(msg.to_vec())
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
