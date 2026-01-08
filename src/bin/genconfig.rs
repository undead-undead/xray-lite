use anyhow::Result;
use serde_json::json;
use uuid::Uuid;

fn main() -> Result<()> {
    println!("========================================");
    println!("配置文件生成工具");
    println!("========================================");
    println!();

    // 生成 UUID
    let uuid = Uuid::new_v4();

    // 生成示例配置
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

    // 输出配置
    println!("生成的配置文件 (config.json):");
    println!("{}", serde_json::to_string_pretty(&config)?);
    println!();
    println!("========================================");
    println!("下一步:");
    println!("========================================");
    println!();
    println!("1. 运行 'cargo run --bin keygen' 生成密钥对");
    println!("2. 将私钥和公钥替换到配置文件中");
    println!("3. 修改 dest 和 serverNames 为你想要伪装的网站");
    println!("4. 保存配置到 config.json");
    println!("5. 运行服务器: cargo run --release");
    println!();

    Ok(())
}
