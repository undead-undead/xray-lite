use anyhow::Result;
use serde_json::json;
use uuid::Uuid;

fn main() -> Result<()> {
    println!("========================================");
    println!("Configuration File Generator");
    println!("========================================");
    println!();

    // Generate UUID
    let uuid = Uuid::new_v4();

    // Generate example configuration
    let config = json!({
        "inbounds": [{
            "protocol": "vless",
            "listen": "0.0.0.0",
            "port": 443,
            "settings": {
                "clients": [{
                    "id": uuid.to_string(),
                    "flow": "",
                    "email": "user@example.com"
                }],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "dest": "www.microsoft.com:443",
                    "serverNames": [
                        "www.microsoft.com",
                        "*.microsoft.com"
                    ],
                    "privateKey": "YOUR_PRIVATE_KEY_HERE",
                    "publicKey": "YOUR_PUBLIC_KEY_HERE",
                    "shortIds": [
                        "0123456789abcdef"
                    ],
                    "fingerprint": "chrome"
                }
            }
        }],
        "outbounds": [{
            "protocol": "freedom",
            "tag": "direct"
        }],
        "routing": {
            "rules": []
        }
    });

    // Output configuration
    println!("Generated Configuration File (config.json):");
    println!("{}", serde_json::to_string_pretty(&config)?);
    println!();
    println!("========================================");
    println!("Next Steps:");
    println!("========================================");
    println!();
    println!("1. Run 'cargo run --bin keygen' to generate key pair");
    println!("2. Replace private and public keys in the configuration");
    println!("3. Modify dest and serverNames to your desired masquerade website");
    println!("4. Save configuration to config.json");
    println!("5. Run server: cargo run --release");
    println!();

    Ok(())
}
