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

    pub async fn perform(&self, mut client_stream: TcpStream) -> Result<super::stream::TlsStream<TcpStream>> {
        // 1. Read ClientHello
        let (client_hello, client_hello_payload) = self.read_client_hello(&mut client_stream).await?;
        debug!("ClientHello received");

        // 2. Extract Client Key Share
        let client_key_share = match client_hello.get_key_share() {
            Some(key) => key,
            None => return Err(anyhow!("No X25519 key share")),
        };

        // 3. Key Exchange
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

        // 5. Send ServerHello & CCS
        client_stream.write_all(&server_hello.encode()).await?;
        client_stream.write_all(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]).await?;
        debug!("ServerHello & CCS sent");

        // 6. Derive Handshake Keys
        let transcript0 = vec![client_hello_payload.as_slice(), server_hello.handshake_payload()];
        let (mut hs_keys, handshake_secret) = TlsKeys::derive_handshake_keys(
            &shared_secret, 
            &super::crypto::hash_transcript(&transcript0)
        )?;
        
        // 7. Build EncryptedExtensions with ALPN
        let mut ee_msg = BytesMut::new();
        ee_msg.put_u8(8); // Handshake Type: EncryptedExtensions
        
        // Build extensions
        let mut extensions = BytesMut::new();
        
        // ALPN Extension (0x0010)
        extensions.put_u16(0x0010); // Extension Type
        
        // ALPN protocol list
        let mut alpn_list = BytesMut::new();
        // Protocol: "h2" (length-prefixed)
        alpn_list.put_u8(2); // Length of "h2"
        alpn_list.put_slice(b"h2");
        // Protocol: "http/1.1" (length-prefixed)
        alpn_list.put_u8(8); // Length of "http/1.1"
        alpn_list.put_slice(b"http/1.1");
        
        // Extension Data Length = ProtocolNameListLength(2) + ProtocolNameList
        let ext_data_len = 2 + alpn_list.len();
        extensions.put_u16(ext_data_len as u16);
        extensions.put_u16(alpn_list.len() as u16); // ProtocolNameListLength
        extensions.put_slice(&alpn_list);
        
        // Handshake message length = ExtensionsLength(2) + Extensions
        let ee_body_len = 2 + extensions.len();
        ee_msg.put_u8(((ee_body_len >> 16) & 0xFF) as u8);
        ee_msg.put_u8(((ee_body_len >> 8) & 0xFF) as u8);
        ee_msg.put_u8((ee_body_len & 0xFF) as u8);
        
        ee_msg.put_u16(extensions.len() as u16); // Extensions Length
        ee_msg.put_slice(&extensions);
        
        // Send EE (Seq 0)
        let ee_record = hs_keys.encrypt_server_record(0, &ee_msg, 22)?;
        client_stream.write_all(&ee_record).await?;
        debug!("EncryptedExtensions sent (seq=0)");
        
        // 8. Certificate (Empty)
        let mut cert_msg = BytesMut::new();
        cert_msg.put_u8(11); // Type: Certificate
        cert_msg.put_u8(0); cert_msg.put_u8(0); cert_msg.put_u8(4); // Length: 4
        cert_msg.put_u8(0); // CertificateRequestContext length: 0
        cert_msg.put_u8(0); cert_msg.put_u8(0); cert_msg.put_u8(0); // CertificateList length: 0
        
        // Send Certificate (Seq 1)
        let cert_record = hs_keys.encrypt_server_record(1, &cert_msg, 22)?;
        client_stream.write_all(&cert_record).await?;
        debug!("Certificate sent (seq=1)");
        
        // 9. Finished
        let transcript1 = vec![
            client_hello_payload.as_slice(), 
            server_hello.handshake_payload(),
            &ee_msg,
            &cert_msg
        ];
        let hash1 = super::crypto::hash_transcript(&transcript1);
        let verify_data = TlsKeys::calculate_verify_data(&hs_keys.server_traffic_secret, &hash1)?;
        
        let mut fin_msg = BytesMut::new();
        fin_msg.put_u8(20); // Type: Finished
        let fin_len = verify_data.len();
        fin_msg.put_u8(((fin_len >> 16) & 0xFF) as u8);
        fin_msg.put_u8(((fin_len >> 8) & 0xFF) as u8);
        fin_msg.put_u8((fin_len & 0xFF) as u8);
        fin_msg.put_slice(&verify_data);
        
        // Send Finished (Seq 2)
        let fin_record = hs_keys.encrypt_server_record(2, &fin_msg, 22)?;
        client_stream.write_all(&fin_record).await?;
        debug!("Finished sent (seq=2)");
        
        info!("Server handshake complete, waiting for client Finished...");

        // 10. Read Client Finished
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
                    warn!("Client Alert: {}/{}", record_data[5], if plen > 1 { record_data[6] } else { 0 });
                    return Err(anyhow!("Client sent Alert"));
                }
                
                if inner_type == 22 && plen > 0 && record_data[5] == 20 {
                    info!("Client Finished received!");
                    break;
                }
            }
        }
        
        // 11. Derive Application Keys
        let transcript_app = vec![
            client_hello_payload.as_slice(), 
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
