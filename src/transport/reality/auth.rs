use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine as _};
use sha2::{Digest, Sha256};

/// Reality 认证密钥派生
pub struct RealityAuth {
    private_key_bytes: Vec<u8>,
}

impl RealityAuth {
    /// 创建新的认证处理器
    pub fn new(private_key: &str) -> Result<Self> {
        // 尝试从 Base64 解码密钥
        let private_key_bytes = if let Ok(decoded) = general_purpose::STANDARD.decode(private_key) {
            if decoded.len() == 32 {
                decoded
            } else {
                return Err(anyhow!(
                    "私钥长度必须是 32 字节，当前: {} 字节",
                    decoded.len()
                ));
            }
        } else if let Ok(decoded) = general_purpose::URL_SAFE_NO_PAD.decode(private_key) {
            // 尝试 URL-safe Base64 (Xray 使用的格式)
            if decoded.len() == 32 {
                decoded
            } else {
                return Err(anyhow!(
                    "私钥长度必须是 32 字节，当前: {} 字节",
                    decoded.len()
                ));
            }
        } else if private_key.len() >= 32 {
            // 如果不是 Base64，直接使用字符串的字节
            private_key.as_bytes()[..32].to_vec()
        } else {
            // 如果私钥太短，用 SHA256 扩展
            let mut hasher = Sha256::new();
            hasher.update(private_key.as_bytes());
            hasher.finalize().to_vec()
        };

        Ok(Self { private_key_bytes })
    }

    /// 生成认证标记
    ///
    /// Reality 使用以下方式生成认证标记:
    /// 1. 从 ClientHello 的 random 字段提取客户端随机数
    /// 2. 使用服务器私钥和客户端随机数生成共享密钥
    /// 3. 使用 HMAC-SHA256 生成认证标记
    pub fn generate_auth_tag(
        &self,
        client_random: &[u8; 32],
        server_random: &[u8; 32],
    ) -> [u8; 32] {
        // 组合客户端和服务器随机数
        let mut combined = Vec::new();
        combined.extend_from_slice(client_random);
        combined.extend_from_slice(server_random);
        combined.extend_from_slice(&self.private_key_bytes);

        // 使用 SHA256 生成认证标记
        let mut hasher = Sha256::new();
        hasher.update(&combined);
        let result = hasher.finalize();

        let mut auth_tag = [0u8; 32];
        auth_tag.copy_from_slice(&result);
        auth_tag
    }

    /// 在 ServerHello 的 random 字段中注入认证信息
    ///
    /// Reality 的做法:
    /// 1. 保留原始 ServerHello 的前 20 字节 random
    /// 2. 将后 12 字节替换为认证标记的前 12 字节
    pub fn inject_auth_into_random(
        &self,
        original_random: &[u8; 32],
        client_random: &[u8; 32],
    ) -> [u8; 32] {
        let auth_tag = self.generate_auth_tag(client_random, original_random);

        let mut modified_random = [0u8; 32];
        // 保留前 20 字节
        modified_random[..20].copy_from_slice(&original_random[..20]);
        // 注入认证标记的前 12 字节
        modified_random[20..32].copy_from_slice(&auth_tag[..12]);

        modified_random
    }

    /// 验证认证标记
    pub fn verify_auth_tag(
        &self,
        client_random: &[u8; 32],
        server_random: &[u8; 32],
        received_tag: &[u8],
    ) -> bool {
        let expected_tag = self.generate_auth_tag(client_random, server_random);

        // 比较前 12 字节
        if received_tag.len() < 12 {
            return false;
        }

        expected_tag[..12] == received_tag[..12]
    }
}

/// 从 ServerHello 数据中提取和修改 random 字段
pub struct ServerHelloModifier {
    auth: RealityAuth,
}

impl ServerHelloModifier {
    pub fn new(private_key: &str) -> Result<Self> {
        Ok(Self {
            auth: RealityAuth::new(private_key)?,
        })
    }

    /// 修改 ServerHello 的 random 字段
    ///
    /// ServerHello 格式:
    /// - Handshake Type (1 byte): 0x02
    /// - Length (3 bytes)
    /// - Version (2 bytes)
    /// - Random (32 bytes) <- 我们要修改这里
    /// - Session ID Length (1 byte)
    /// - Session ID (variable)
    /// - Cipher Suite (2 bytes)
    /// - Compression Method (1 byte)
    /// - Extensions Length (2 bytes)
    /// - Extensions (variable)
    pub fn modify_server_hello(
        &self,
        server_hello_data: &mut [u8],
        client_random: &[u8; 32],
    ) -> Result<()> {
        // ServerHello 最小长度检查
        if server_hello_data.len() < 38 {
            return Err(anyhow!("ServerHello 数据太短"));
        }

        // 检查是否是 ServerHello (type = 0x02)
        if server_hello_data[0] != 0x02 {
            return Err(anyhow!("不是 ServerHello 消息"));
        }

        // Random 字段从第 6 字节开始 (跳过 type(1) + length(3) + version(2))
        let random_offset = 6;

        if server_hello_data.len() < random_offset + 32 {
            return Err(anyhow!("ServerHello 数据不完整"));
        }

        // 提取原始 random
        let mut original_random = [0u8; 32];
        original_random.copy_from_slice(&server_hello_data[random_offset..random_offset + 32]);

        // 生成修改后的 random
        let modified_random = self
            .auth
            .inject_auth_into_random(&original_random, client_random);

        // 替换 random 字段
        server_hello_data[random_offset..random_offset + 32].copy_from_slice(&modified_random);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_tag_generation() {
        let auth = RealityAuth::new("test_private_key_32_bytes_long!").unwrap();

        let client_random = [1u8; 32];
        let server_random = [2u8; 32];

        let tag1 = auth.generate_auth_tag(&client_random, &server_random);
        let tag2 = auth.generate_auth_tag(&client_random, &server_random);

        // 相同输入应该产生相同输出
        assert_eq!(tag1, tag2);
    }

    #[test]
    fn test_auth_injection() {
        let auth = RealityAuth::new("test_private_key_32_bytes_long!").unwrap();

        let client_random = [1u8; 32];
        let original_random = [2u8; 32];

        let modified = auth.inject_auth_into_random(&original_random, &client_random);

        // 前 20 字节应该保持不变
        assert_eq!(&modified[..20], &original_random[..20]);

        // 后 12 字节应该被修改
        assert_ne!(&modified[20..], &original_random[20..]);
    }

    #[test]
    fn test_server_hello_modification() {
        let modifier = ServerHelloModifier::new("test_private_key_32_bytes_long!").unwrap();

        // 构造一个简单的 ServerHello
        let mut server_hello = vec![
            0x02, // Handshake Type: ServerHello
            0x00, 0x00, 0x46, // Length: 70 bytes
            0x03, 0x03, // Version: TLS 1.2
        ];

        // 添加 32 字节 random
        server_hello.extend_from_slice(&[0x42u8; 32]);

        // 添加其他字段 (session id, cipher suite, etc.)
        server_hello.extend_from_slice(&[
            0x00, // Session ID Length: 0
            0x13, 0x01, // Cipher Suite: TLS_AES_128_GCM_SHA256
            0x00, // Compression Method: null
            0x00, 0x00, // Extensions Length: 0
        ]);

        let client_random = [0x11u8; 32];
        let original_random = server_hello[6..38].to_vec();

        // 修改 ServerHello
        modifier
            .modify_server_hello(&mut server_hello, &client_random)
            .unwrap();

        // 验证前 20 字节保持不变
        assert_eq!(&server_hello[6..26], &original_random[..20]);

        // 验证后 12 字节被修改
        assert_ne!(&server_hello[26..38], &original_random[20..32]);
    }
}
