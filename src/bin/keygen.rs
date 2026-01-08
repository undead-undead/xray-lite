use anyhow::Result;
use base64::{engine::general_purpose, Engine as _};
use rand::rngs::OsRng;
use rand::RngCore;
use x25519_dalek::PublicKey;

fn main() -> Result<()> {
    println!("========================================");
    println!("Xray Reality 密钥生成工具");
    println!("========================================");
    println!();

    // 生成 32 字节随机私钥
    let mut private_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut private_bytes);

    // 计算公钥
    let public_key = PublicKey::from(private_bytes);
    let public_bytes = public_key.as_bytes();

    // 编码为 Base64 (URL-safe, no padding - Xray 格式)
    let private_b64 = general_purpose::URL_SAFE_NO_PAD.encode(private_bytes);
    let public_b64 = general_purpose::URL_SAFE_NO_PAD.encode(public_bytes);

    // 输出
    println!("Private key: {}", private_b64);
    println!("Public key:  {}", public_b64);
    println!();
    println!("========================================");
    println!("使用说明:");
    println!("========================================");
    println!();
    println!("1. 服务器配置 (config.json):");
    println!("   \"realitySettings\": {{");
    println!("     \"privateKey\": \"{}\"", private_b64);
    println!("   }}");
    println!();
    println!("2. 客户端配置 (Xray):");
    println!("   \"realitySettings\": {{");
    println!("     \"publicKey\": \"{}\"", public_b64);
    println!("   }}");
    println!();
    println!("注意: 请妥善保管私钥，不要泄露！");
    println!();

    Ok(())
}
