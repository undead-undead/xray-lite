use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine as _};
use ring::hmac;

/// Reality 认证密钥派生
pub struct RealityAuth {
    private_key_bytes: Vec<u8>,
}

impl RealityAuth {
    /// 创建新的认证处理器
    pub fn new(private_key: &str) -> Result<Self> {
        let private_key_bytes = if let Ok(decoded) = general_purpose::STANDARD.decode(private_key) {
            decoded
        } else if let Ok(decoded) = general_purpose::URL_SAFE_NO_PAD.decode(private_key) {
            decoded
        } else {
            return Err(anyhow!("Reality 密钥格式不正确，必须是 Base64"));
        };

        if private_key_bytes.len() != 32 {
            return Err(anyhow!(
                "私钥长度必须是 32 字节，当前: {} 字节",
                private_key_bytes.len()
            ));
        }

        Ok(Self { private_key_bytes })
    }

    /// 生成认证标记 (v0.1.15 以后使用标准 Reality HMAC 算法)
    ///
    /// Reality 的做法:
    /// HMAC-SHA256(key=private_key, message=server_random[0..20] + client_random[0..32])
    pub fn generate_auth_tag(
        &self,
        client_random: &[u8; 32],
        server_random_20: &[u8; 20],
    ) -> [u8; 32] {
        let key = hmac::Key::new(hmac::HMAC_SHA256, &self.private_key_bytes);

        let mut msg = Vec::with_capacity(20 + 32);
        msg.extend_from_slice(server_random_20);
        msg.extend_from_slice(client_random);

        let signature = hmac::sign(&key, &msg);
        let mut auth_tag = [0u8; 32];
        auth_tag.copy_from_slice(signature.as_ref());
        auth_tag
    }

    /// 在 ServerHello 的 random 字段中注入认证信息
    pub fn inject_auth_into_random(
        &self,
        original_random: &[u8; 32],
        client_random: &[u8; 32],
    ) -> [u8; 32] {
        // 核心修正: 只取 original_random 的前 20 字节作为 HMAC 输入的一部分
        let auth_tag =
            self.generate_auth_tag(client_random, original_random[..20].try_into().unwrap());

        let mut modified_random = [0u8; 32];
        modified_random[..20].copy_from_slice(&original_random[..20]);
        modified_random[20..32].copy_from_slice(&auth_tag[..12]);

        modified_random
    }

    pub fn verify_client_auth(&self, client_random: &[u8; 32], session_id: &[u8]) -> bool {
        if session_id.len() < 8 {
            return false;
        }

        // 计算期望的认证标记
        let key = hmac::Key::new(hmac::HMAC_SHA256, &self.private_key_bytes);
        let signature = hmac::sign(&key, client_random);

        // 使用常数时间比较前 8 字节
        use subtle::ConstantTimeEq;
        signature.as_ref()[..8].ct_eq(&session_id[..8]).into()
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

    pub fn modify_server_hello(
        &self,
        server_hello_data: &mut [u8],
        client_random: &[u8; 32],
    ) -> Result<()> {
        if server_hello_data.len() < 38 {
            return Err(anyhow!("ServerHello 数据太短"));
        }

        if server_hello_data[0] != 0x02 {
            return Err(anyhow!("不是 ServerHello 消息"));
        }

        let random_offset = 6;
        let mut original_random = [0u8; 32];
        original_random.copy_from_slice(&server_hello_data[random_offset..random_offset + 32]);

        let modified_random = self
            .auth
            .inject_auth_into_random(&original_random, client_random);

        server_hello_data[random_offset..random_offset + 32].copy_from_slice(&modified_random);
        Ok(())
    }
}
