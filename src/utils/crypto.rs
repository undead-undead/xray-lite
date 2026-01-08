use base64::{engine::general_purpose, Engine as _};
use rand::rngs::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey};

/// X25519 密钥对
pub struct X25519KeyPair {
    pub private_key: EphemeralSecret,
    pub public_key: PublicKey,
}

/// 生成 X25519 密钥对
pub fn generate_x25519_keypair() -> X25519KeyPair {
    let private_key = EphemeralSecret::random_from_rng(OsRng);
    let public_key = PublicKey::from(&private_key);

    X25519KeyPair {
        private_key,
        public_key,
    }
}

/// 将公钥转换为 Base64 字符串
pub fn public_key_to_base64(public_key: &PublicKey) -> String {
    general_purpose::STANDARD.encode(public_key.as_bytes())
}

/// 将私钥转换为 Base64 字符串 (注意: EphemeralSecret 不能导出)
pub fn private_key_to_base64(private_key_bytes: &[u8; 32]) -> String {
    general_purpose::STANDARD.encode(private_key_bytes)
}

/// 从 Base64 字符串解析公钥
pub fn public_key_from_base64(s: &str) -> Result<PublicKey, base64::DecodeError> {
    let bytes = general_purpose::STANDARD.decode(s)?;
    let mut array = [0u8; 32];
    array.copy_from_slice(&bytes[..32]);
    Ok(PublicKey::from(array))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = generate_x25519_keypair();

        // 验证密钥长度
        assert_eq!(keypair.public_key.as_bytes().len(), 32);
    }

    #[test]
    fn test_public_key_base64() {
        let keypair = generate_x25519_keypair();

        // 测试公钥编解码
        let pub_b64 = public_key_to_base64(&keypair.public_key);
        let decoded_pub = public_key_from_base64(&pub_b64).unwrap();
        assert_eq!(keypair.public_key.as_bytes(), decoded_pub.as_bytes());
    }
}
