use anyhow::Result;
use base64::{engine::general_purpose, Engine as _};
use rand::rngs::OsRng;
use rand::RngCore;
use x25519_dalek::{PublicKey, StaticSecret};

fn main() -> Result<()> {
    println!("========================================");
    println!("Xray Reality Key Generation Tool");
    println!("========================================");
    println!();

    // Generate random static secret (private key)
    let secret = StaticSecret::random_from_rng(OsRng);
    let private_bytes = secret.to_bytes();

    // Calculate public key
    let public_key = PublicKey::from(&secret);
    let public_bytes = public_key.as_bytes();

    // Encode to Base64 (URL-safe, no padding - Xray format)
    let private_b64 = general_purpose::URL_SAFE_NO_PAD.encode(private_bytes);
    let public_b64 = general_purpose::URL_SAFE_NO_PAD.encode(public_bytes);

    // Output
    println!("Private key: {}", private_b64);
    println!("Public key:  {}", public_b64);
    println!();
    println!("========================================");
    println!("Usage Instructions:");
    println!("========================================");
    println!();
    println!("1. Server Configuration (config.json):");
    println!("   \"realitySettings\": {{");
    println!("     \"privateKey\": \"{}\"", private_b64);
    println!("   }}");
    println!();
    println!("2. Client Configuration (Xray):");
    println!("   \"realitySettings\": {{");
    println!("     \"publicKey\": \"{}\"", public_b64);
    println!("   }}");
    println!();
    println!("Note: Keep the private key secure and do not share it!");
    println!();

    Ok(())
}
