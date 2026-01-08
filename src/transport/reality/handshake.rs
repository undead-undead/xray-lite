use anyhow::{anyhow, Result};
use bytes::BytesMut;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

use super::tls::{ClientHello, ContentType, ServerHello, TlsRecord};
use super::RealityConfig;

/// Reality 握手处理器
#[derive(Clone)]
pub struct RealityHandshake {
    config: RealityConfig,
}

impl RealityHandshake {
    pub fn new(config: RealityConfig) -> Self {
        Self { config }
    }

    /// 执行 Reality TLS 握手
    pub async fn perform(&self, mut client_stream: TcpStream) -> Result<TcpStream> {
        info!("开始 Reality TLS 握手");

        // Step 1: 读取客户端的 ClientHello
        let (client_hello, client_hello_record) = self.read_client_hello(&mut client_stream).await?;
        debug!("收到 ClientHello");

        // Step 2: 验证 SNI
        let sni = client_hello
            .get_sni()
            .ok_or_else(|| anyhow!("ClientHello 中没有 SNI"))?;
        debug!("SNI: {}", sni);

        if !self.validate_sni(&sni) {
            warn!("SNI 验证失败: {}", sni);
            // 对于非法客户端，转发到真实网站
            return self.forward_to_dest(client_stream, &client_hello_record).await;
        }

        // Step 3: 验证 Reality short_id
        // 注意：Reality 的 Short ID 实际上是 Session ID 的前缀
        // 我们需要检查 session_id 是否以配置中的任何一个 Short ID 开头
        if !self.validate_short_id(&client_hello.session_id) {
             let received_hex = hex::encode(&client_hello.session_id);
             warn!(
                 "Short ID 验证失败. 收到(Session ID): {}, 期望前缀之一: {:?}",
                 received_hex,
                 self.config.short_ids
             );
             return self.forward_to_dest(client_stream, &client_hello_record).await;
        }
        debug!("Short ID 验证成功");

        // Step 4: 连接到真实网站获取 ServerHello
        let mut dest_stream = TcpStream::connect(&self.config.dest).await?;
        debug!("已连接到目标网站: {}", self.config.dest);

        // 转发 ClientHello 到真实网站
        dest_stream.write_all(&client_hello_record.encode()).await?;

        // Step 5: 读取真实网站的 ServerHello
        let server_hello_record = self.read_server_hello(&mut dest_stream).await?;
        debug!("收到真实网站的 ServerHello");

        // Step 6: 修改 ServerHello (注入 Reality 认证)
        let modified_server_hello = self.modify_server_hello(server_hello_record, client_hello.get_random())?;
        debug!("ServerHello 已修改");

        // Step 7: 发送修改后的 ServerHello 给客户端
        client_stream.write_all(&modified_server_hello.encode()).await?;
        debug!("已发送修改后的 ServerHello 给客户端");

        // Step 8: 读取并转发 ChangeCipherSpec 和其他握手消息
        self.relay_handshake_messages(&mut dest_stream, &mut client_stream)
            .await?;

        info!("Reality TLS 握手完成");

        // 关闭与真实网站的连接，返回客户端连接
        drop(dest_stream);

        Ok(client_stream)
    }

    /// 读取 ClientHello
    async fn read_client_hello(
        &self,
        stream: &mut TcpStream,
    ) -> Result<(ClientHello, TlsRecord)> {
        let mut buffer = BytesMut::with_capacity(16384);

        loop {
            let n = stream.read_buf(&mut buffer).await?;
            if n == 0 {
                return Err(anyhow!("连接已关闭"));
            }

            if let Some(record) = TlsRecord::parse(&mut buffer)? {
                if record.content_type == ContentType::Handshake {
                    let client_hello = ClientHello::parse(&record.payload)?;
                    return Ok((client_hello, record));
                }
            }
        }
    }

    /// 读取 ServerHello
    async fn read_server_hello(&self, stream: &mut TcpStream) -> Result<TlsRecord> {
        let mut buffer = BytesMut::with_capacity(16384);

        loop {
            let n = stream.read_buf(&mut buffer).await?;
            if n == 0 {
                return Err(anyhow!("连接已关闭"));
            }

            if let Some(record) = TlsRecord::parse(&mut buffer)? {
                if record.content_type == ContentType::Handshake {
                    return Ok(record);
                }
            }
        }
    }

    /// 修改 ServerHello
    fn modify_server_hello(&self, record: TlsRecord, client_random: &[u8; 32]) -> Result<TlsRecord> {
        // 创建 ServerHello 对象
        let mut server_hello = ServerHello::from_raw(record.payload);

        // 使用私钥和客户端 random 修改 ServerHello
        server_hello.modify_for_reality(&self.config.private_key, client_random)?;

        // 返回修改后的记录
        Ok(TlsRecord {
            content_type: record.content_type,
            version: record.version,
            payload: server_hello.raw_data,
        })
    }

    /// 转发握手消息 (ChangeCipherSpec, Certificate, Finished 等)
    async fn relay_handshake_messages(
        &self,
        dest_stream: &mut TcpStream,
        client_stream: &mut TcpStream,
    ) -> Result<()> {
        let mut buffer = BytesMut::with_capacity(16384);
        let mut messages_count = 0;
        const MAX_HANDSHAKE_MESSAGES: usize = 10; // 限制握手消息数量

        // 读取并转发剩余的握手消息
        while messages_count < MAX_HANDSHAKE_MESSAGES {
            tokio::select! {
                result = dest_stream.read_buf(&mut buffer) => {
                    let n = result?;
                    if n == 0 {
                        break;
                    }

                    // 转发到客户端
                    client_stream.write_all(&buffer[..n]).await?;
                    buffer.clear();
                    messages_count += 1;

                    // 如果收到 Finished 消息，握手完成
                    // TODO: 更精确地检测握手完成
                    if messages_count >= 3 {
                        break;
                    }
                }
                _ = tokio::time::sleep(tokio::time::Duration::from_secs(2)) => {
                    // 超时，认为握手完成
                    break;
                }
            }
        }

        Ok(())
    }

    /// 转发到真实网站 (对于非法客户端)
    async fn forward_to_dest(
        &self,
        mut client_stream: TcpStream,
        client_hello: &TlsRecord,
    ) -> Result<TcpStream> {
        warn!("转发非法客户端到真实网站");

        let mut dest_stream = TcpStream::connect(&self.config.dest).await?;

        // 转发 ClientHello
        dest_stream.write_all(&client_hello.encode()).await?;

        // 双向转发
        tokio::spawn(async move {
            let _ = tokio::io::copy_bidirectional(&mut client_stream, &mut dest_stream).await;
        });

        // 返回一个已关闭的流 (因为我们已经转发了)
        Err(anyhow!("客户端已转发到真实网站"))
    }

    /// 验证 SNI
    fn validate_sni(&self, sni: &str) -> bool {
        self.config.server_names.iter().any(|name| {
            if name.starts_with('*') {
                // 通配符匹配
                let suffix = &name[1..];
                sni.ends_with(suffix)
            } else {
                // 精确匹配
                sni == name
            }
        })
    }

    /// 验证 short_id (Session ID)
    fn validate_short_id(&self, session_id: &[u8]) -> bool {
        // 如果配置为空，则允许所有 (或者你可以选择拒绝所有，通常 Reality 需要 Short ID)
        if self.config.short_ids.is_empty() {
            return true;
        }

        let session_id_hex = hex::encode(session_id);
        self.config.short_ids.iter().any(|id| {
            // 检查 session_id_hex 是否以 id 开头
            session_id_hex.to_lowercase().starts_with(&id.to_lowercase())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> RealityConfig {
        RealityConfig {
            dest: "www.apple.com:443".to_string(),
            server_names: vec!["www.apple.com".to_string(), "*.apple.com".to_string()],
            private_key: "test_private_key_32_bytes_long!".to_string(),
            public_key: Some("test_public_key".to_string()),
            short_ids: vec!["0123456789abcdef".to_string()],
            fingerprint: "chrome".to_string(),
        }
    }

    #[test]
    fn test_validate_sni() {
        let config = create_test_config();
        let handshake = RealityHandshake::new(config);

        assert!(handshake.validate_sni("www.apple.com"));
        assert!(handshake.validate_sni("store.apple.com"));
        assert!(!handshake.validate_sni("www.google.com"));
    }

    #[test]
    fn test_validate_short_id() {
        let config = create_test_config();
        let handshake = RealityHandshake::new(config);

        let valid_id = hex::decode("0123456789abcdef").unwrap();
        let invalid_id = hex::decode("fedcba9876543210").unwrap();

        assert!(handshake.validate_short_id(&valid_id));
        assert!(!handshake.validate_short_id(&invalid_id));
    }
}
