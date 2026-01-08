#!/bin/bash

# Reality 服务器一键部署脚本

set -e

# 颜色定义
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo "========================================="
echo -e "${BLUE}Reality 服务器一键部署${NC}"
echo "========================================="
echo ""

# 检查是否已有配置文件
if [ -f "config.json" ]; then
    echo -e "${YELLOW}检测到已存在 config.json${NC}"
    read -p "是否覆盖? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "保留现有配置"
        USE_EXISTING=true
    else
        USE_EXISTING=false
    fi
else
    USE_EXISTING=false
fi

# 生成密钥对
echo -e "${YELLOW}[1/5] 生成 X25519 密钥对...${NC}"
cargo build --release --bin keygen > /dev/null 2>&1
KEYGEN_OUTPUT=$(./target/release/keygen)
echo "$KEYGEN_OUTPUT"

# 提取密钥
PRIVATE_KEY=$(echo "$KEYGEN_OUTPUT" | grep "Private key:" | awk '{print $3}')
PUBLIC_KEY=$(echo "$KEYGEN_OUTPUT" | grep "Public key:" | awk '{print $3}')

echo ""
echo -e "${GREEN}✓ 密钥生成成功${NC}"
echo ""

# 生成 UUID
echo -e "${YELLOW}[2/5] 生成客户端 UUID...${NC}"
CLIENT_UUID=$(uuidgen 2>/dev/null || python3 -c "import uuid; print(uuid.uuid4())")
echo "UUID: $CLIENT_UUID"
echo -e "${GREEN}✓ UUID 生成成功${NC}"
echo ""

# 询问配置参数
echo -e "${YELLOW}[3/5] 配置参数...${NC}"

if [ "$USE_EXISTING" = false ]; then
    read -p "监听端口 [443]: " PORT
    PORT=${PORT:-443}

    read -p "伪装网站 [www.microsoft.com:443]: " DEST
    DEST=${DEST:-www.microsoft.com:443}

    # 从 DEST 提取域名
    DOMAIN=$(echo $DEST | cut -d: -f1)

    read -p "Short ID [0123456789abcdef]: " SHORT_ID
    SHORT_ID=${SHORT_ID:-0123456789abcdef}

    # 生成配置文件
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

    echo -e "${GREEN}✓ 配置文件已生成: config.json${NC}"
fi
echo ""

# 编译服务器
echo -e "${YELLOW}[4/5] 编译服务器...${NC}"
cargo build --release
echo -e "${GREEN}✓ 编译成功${NC}"
echo ""

# 生成客户端配置
echo -e "${YELLOW}[5/5] 生成客户端配置...${NC}"

# 获取服务器 IP
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

echo -e "${GREEN}✓ 客户端配置已生成: client-config.json${NC}"
echo ""

# 显示总结
echo "========================================="
echo -e "${GREEN}部署完成！${NC}"
echo "========================================="
echo ""
echo -e "${BLUE}服务器信息:${NC}"
echo "  端口: ${PORT:-443}"
echo "  伪装网站: ${DEST:-www.microsoft.com:443}"
echo "  UUID: $CLIENT_UUID"
echo ""
echo -e "${BLUE}启动服务器:${NC}"
echo "  ./target/release/vless-server --config config.json"
echo ""
echo -e "${BLUE}客户端配置:${NC}"
echo "  配置文件: client-config.json"
echo "  使用 Xray 客户端加载此配置"
echo ""
echo -e "${YELLOW}注意事项:${NC}"
echo "  1. 请确保防火墙开放端口 ${PORT:-443}"
echo "  2. 建议使用 systemd 管理服务器进程"
echo "  3. 定期备份配置文件"
echo ""
