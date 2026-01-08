#!/bin/bash

# Xray-Lite One-Click Deployment Script
# Xray-Lite 一键部署脚本

set -e

# Color definitions / 颜色定义
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}=========================================${NC}"
echo -e "${BLUE}  Xray-Lite One-Click Deployment${NC}"
echo -e "${BLUE}  Xray-Lite 一键部署${NC}"
echo -e "${BLUE}=========================================${NC}"
echo ""

# Check if config.json already exists / 检查是否已有配置文件
if [ -f "config.json" ]; then
    echo -e "${YELLOW}Detected existing config.json / 检测到已存在 config.json${NC}"
    read -p "Overwrite? / 是否覆盖? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Keeping existing configuration / 保留现有配置"
        USE_EXISTING=true
    else
        USE_EXISTING=false
    fi
else
    USE_EXISTING=false
fi

# Generate key pair / 生成密钥对
echo -e "${YELLOW}[1/5] Generating X25519 key pair... / 生成 X25519 密钥对...${NC}"
cargo build --release --bin keygen > /dev/null 2>&1
KEYGEN_OUTPUT=$(./target/release/keygen)
echo "$KEYGEN_OUTPUT"

# Extract keys / 提取密钥
PRIVATE_KEY=$(echo "$KEYGEN_OUTPUT" | grep "Private key:" | awk '{print $3}')
PUBLIC_KEY=$(echo "$KEYGEN_OUTPUT" | grep "Public key:" | awk '{print $3}')

echo ""
echo -e "${GREEN}✓ Key generation successful / 密钥生成成功${NC}"
echo ""

# Generate UUID / 生成 UUID
echo -e "${YELLOW}[2/5] Generating client UUID... / 生成客户端 UUID...${NC}"
CLIENT_UUID=$(uuidgen 2>/dev/null || python3 -c "import uuid; print(uuid.uuid4())")
echo "UUID: $CLIENT_UUID"
echo -e "${GREEN}✓ UUID generation successful / UUID 生成成功${NC}"
echo ""

# Configuration parameters / 配置参数
echo -e "${YELLOW}[3/5] Configuration parameters... / 配置参数...${NC}"

if [ "$USE_EXISTING" = false ]; then
    read -p "Listening port / 监听端口 [443]: " PORT
    PORT=${PORT:-443}

    read -p "Masquerade website / 伪装网站 [www.microsoft.com:443]: " DEST
    DEST=${DEST:-www.microsoft.com:443}

    # Extract domain from DEST / 从 DEST 提取域名
    DOMAIN=$(echo $DEST | cut -d: -f1)

    read -p "Short ID [0123456789abcdef]: " SHORT_ID
    SHORT_ID=${SHORT_ID:-0123456789abcdef}

    # Generate configuration file / 生成配置文件
    cat > config.json << EOF
{
  "inbounds": [
    {
      "protocol": "vless",
      "listen": "0.0.0.0",
      "port": $PORT,
      "settings": {
        "clients": [
          {
            "id": "$CLIENT_UUID",
            "flow": "",
            "email": "user@example.com"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "dest": "$DEST",
          "serverNames": [
            "$DOMAIN",
            "*.$DOMAIN"
          ],
          "privateKey": "$PRIVATE_KEY",
          "publicKey": "$PUBLIC_KEY",
          "shortIds": [
            "$SHORT_ID"
          ],
          "fingerprint": "chrome"
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct"
    }
  ],
  "routing": {
    "rules": []
  }
}
EOF

    echo -e "${GREEN}✓ Configuration file generated: config.json / 配置文件已生成: config.json${NC}"
fi
echo ""

# Build server / 编译服务器
echo -e "${YELLOW}[4/5] Building server... / 编译服务器...${NC}"
cargo build --release
echo -e "${GREEN}✓ Build successful / 编译成功${NC}"
echo ""

# Generate client configuration / 生成客户端配置
echo -e "${YELLOW}[5/5] Generating client configuration... / 生成客户端配置...${NC}"

# Get server IP / 获取服务器 IP
SERVER_IP=$(curl -s ifconfig.me 2>/dev/null || echo "YOUR_SERVER_IP")

cat > client-config.json << EOF
{
  "log": {
    "loglevel": "info"
  },
  "inbounds": [
    {
      "port": 1080,
      "listen": "127.0.0.1",
      "protocol": "socks",
      "settings": {
        "udp": true
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "$SERVER_IP",
            "port": ${PORT:-443},
            "users": [
              {
                "id": "$CLIENT_UUID",
                "encryption": "none",
                "flow": ""
              }
            ]
          }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "fingerprint": "chrome",
          "serverName": "${DOMAIN:-www.microsoft.com}",
          "publicKey": "$PUBLIC_KEY",
          "shortId": "${SHORT_ID:-0123456789abcdef}",
          "spiderX": "/"
        }
      }
    }
  ]
}
EOF

echo -e "${GREEN}✓ Client configuration generated: client-config.json / 客户端配置已生成: client-config.json${NC}"
echo ""

# Summary / 显示总结
echo "========================================="
echo -e "${GREEN}Deployment Complete! / 部署完成！${NC}"
echo "========================================="
echo ""
echo -e "${BLUE}Server Information / 服务器信息:${NC}"
echo "  Port / 端口: ${PORT:-443}"
echo "  Masquerade / 伪装网站: ${DEST:-www.microsoft.com:443}"
echo "  UUID: $CLIENT_UUID"
echo ""
echo -e "${BLUE}Start Server / 启动服务器:${NC}"
echo "  ./target/release/vless-server --config config.json"
echo ""
echo -e "${BLUE}Client Configuration / 客户端配置:${NC}"
echo "  Configuration file / 配置文件: client-config.json"
echo "  Use Xray client to load this configuration"
echo "  使用 Xray 客户端加载此配置"
echo ""
echo -e "${YELLOW}Notes / 注意事项:${NC}"
echo "  1. Ensure firewall port ${PORT:-443} is open / 请确保防火墙开放端口 ${PORT:-443}"
echo "  2. Recommended to use systemd to manage server process / 建议使用 systemd 管理服务器进程"
echo "  3. Backup configuration files regularly / 定期备份配置文件"
echo ""
