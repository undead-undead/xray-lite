#!/bin/bash

# Xray-Lite One-Click Installation Script
# Xray-Lite 一键安装脚本
# 
# Usage / 用法:
#   curl -fsSL https://raw.githubusercontent.com/undead-undead/xray-lite/main/install.sh | bash
#
# Or / 或者:
#   wget -qO- https://raw.githubusercontent.com/undead-undead/xray-lite/main/install.sh | bash

set -e

# Color definitions / 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Version / 版本
VERSION="v0.2.63"
REPO="undead-undead/xray-lite"

echo -e "${BLUE}=========================================${NC}"
echo -e "${BLUE}  Xray-Lite One-Click Installation${NC}"
echo -e "${BLUE}  Xray-Lite 一键安装${NC}"
echo -e "${BLUE}  Version / 版本: ${VERSION}${NC}"
echo -e "${BLUE}=========================================${NC}"
echo ""

# Check if running as root / 检查是否为 root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Please run as root / 请使用 root 权限运行${NC}"
    echo "sudo bash install.sh"
    exit 1
fi

# Detect architecture / 检测架构
ARCH=$(uname -m)
case $ARCH in
    x86_64)
        BINARY_ARCH="x86_64"
        ;;
    aarch64|arm64)
        BINARY_ARCH="aarch64"
        ;;
    *)
        echo -e "${RED}Unsupported architecture: $ARCH / 不支持的架构: $ARCH${NC}"
        exit 1
        ;;
esac

echo -e "${GREEN}Detected architecture / 检测到架构: $ARCH${NC}"
echo ""

# Stop existing service / 停止现有服务
echo -e "${YELLOW}Checking for existing installation... / 检查现有安装...${NC}"
if systemctl is-active --quiet xray-lite; then
    echo "Stopping existing xray-lite service... / 停止现有 xray-lite 服务..."
    systemctl stop xray-lite
    systemctl disable xray-lite
fi

# Kill any lingering vless-server processes
pkill -f vless-server || true

echo ""

# Create installation directory / 创建安装目录
INSTALL_DIR="/opt/xray-lite"
echo -e "${YELLOW}[1/6] Creating installation directory... / 创建安装目录...${NC}"
mkdir -p $INSTALL_DIR
cd $INSTALL_DIR
echo -e "${GREEN}✓ Directory created / 目录已创建: $INSTALL_DIR${NC}"
echo ""

# Download binary / 下载二进制文件
echo -e "${YELLOW}[2/6] Downloading Xray-Lite binary... / 下载 Xray-Lite 二进制文件...${NC}"

DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/xray-lite-${BINARY_ARCH}-unknown-linux-gnu.tar.gz"
FALLBACK_URL="https://raw.githubusercontent.com/${REPO}/main/xray-lite-${BINARY_ARCH}-unknown-linux-gnu.tar.gz?t=$(date +%s)"
# Fallback to release_artifacts in main repo if root raw failed; use timestamp to bust cache
FALLBACK_RA_URL="https://raw.githubusercontent.com/${REPO}/main/release_artifacts/xray-lite-${BINARY_ARCH}-unknown-linux-gnu.tar.gz?t=$(date +%s)"

download_file() {
    local url=$1
    local output=$2
    
    # Try curl first with --fail to handle 404s correctly
    if command -v curl &> /dev/null; then
        if curl -L -f --progress-bar "$url" -o "$output"; then
            return 0
        else
            rm -f "$output" # Ensure no partial/error file is left
            return 1
        fi
    elif command -v wget &> /dev/null; then
        if wget -q --show-progress "$url" -O "$output"; then
            return 0
        else
            rm -f "$output"
            return 1
        fi
    else
        return 1
    fi
}

# Function to check if file is valid gzip
is_valid_gzip() {
    local file=$1
    if gzip -t "$file" >/dev/null 2>&1; then
        return 0
    else
        echo -e "${YELLOW}Warning: Downloaded file is not a valid gzip package.${NC}"
        rm -f "$file"
        return 1
    fi
}

echo "Attempting download..."

# Try Release URL first
if download_file "$DOWNLOAD_URL" "xray-lite.tar.gz" && is_valid_gzip "xray-lite.tar.gz"; then
    echo -e "${GREEN}✓ Download complete (Release)${NC}"
else
    echo -e "${YELLOW}Release download failed/invalid, trying fallback to raw artifacts...${NC}"
    # Try Fallback URL
    if download_file "$FALLBACK_RA_URL" "xray-lite.tar.gz" && is_valid_gzip "xray-lite.tar.gz"; then
         echo -e "${GREEN}✓ Download complete (Artifacts)${NC}"
    else
         echo -e "${RED}Download failed! Could not retrieve valid binary.${NC}"
         echo "Please check your network or try again later."
         exit 1
    fi
fi

echo ""

# Extract binary / 解压二进制文件
echo -e "${YELLOW}[3/6] Extracting files... / 解压文件...${NC}"
tar -xzf xray-lite.tar.gz
rm xray-lite.tar.gz
chmod +x vless-server keygen
echo -e "${GREEN}✓ Files extracted / 文件已解压${NC}"
echo ""

# Generate configuration / 生成配置
echo -e "${YELLOW}[4/6] Generating configuration... / 生成配置...${NC}"

# Generate keys / 生成密钥
echo "Generating X25519 key pair... / 生成 X25519 密钥对..."
KEYGEN_OUTPUT=$(./keygen)
PRIVATE_KEY=$(echo "$KEYGEN_OUTPUT" | grep "Private key:" | awk '{print $3}')
PUBLIC_KEY=$(echo "$KEYGEN_OUTPUT" | grep "Public key:" | awk '{print $3}')

# Generate UUID / 生成 UUID
CLIENT_UUID=$(cat /proc/sys/kernel/random/uuid)

# Get server IP / 获取服务器 IP
SERVER_IP=$(curl -s ifconfig.me 2>/dev/null || curl -s ip.sb 2>/dev/null || echo "YOUR_SERVER_IP")

# Interactive configuration / 交互式配置
echo ""
if [ -t 0 ]; then
    read -p "Server port / 服务器端口 [443]: " PORT_INPUT
    PORT=${PORT_INPUT:-443}
else
    PORT=443
    echo "Non-interactive mode detected using default port 443 / 检测到非交互模式，使用默认端口 443"
fi

if [[ ! "$PORT" =~ ^[0-9]+$ ]]; then
    echo -e "${YELLOW}Invalid port, using default 443 / 端口无效，使用默认 443${NC}"
    PORT=443
fi

if [ -t 0 ]; then
    read -p "Masquerade website / 伪装网站 [www.microsoft.com:443]: " DEST_INPUT
    DEST=${DEST_INPUT:-www.microsoft.com:443}
else
    DEST="www.microsoft.com:443"
fi

DOMAIN=$(echo $DEST | cut -d: -f1)

# Short ID configuration
if command -v openssl &> /dev/null; then
    SHORT_ID=$(openssl rand -hex 8)
else
    SHORT_ID=$(cat /proc/sys/kernel/random/uuid | tr -d '-' | head -c 16)
fi

# XHTTP configuration / XHTTP 配置
ENABLE_XHTTP="n"
NETWORK_TYPE="tcp"
XHTTP_MODE="auto"
XHTTP_PATH="/"

if [ -t 0 ]; then
    echo ""
    echo -e "${YELLOW}XHTTP provides additional obfuscation via HTTP/2${NC}"
    echo -e "${YELLOW}XHTTP 通过 HTTP/2 提供额外的混淆${NC}"
    read -p "Enable XHTTP? / 启用 XHTTP? (y/N): " XHTTP_INPUT
    ENABLE_XHTTP=$(echo "${XHTTP_INPUT:-n}" | tr '[:upper:]' '[:lower:]')
    
    if [ "$ENABLE_XHTTP" = "y" ]; then
        NETWORK_TYPE="http"
        echo ""
        echo "XHTTP modes / XHTTP 模式:"
        echo "  1. auto (recommended / 推荐)"
        echo "  2. stream-up"
        echo "  3. stream-down"  
        echo "  4. stream-one"
        read -p "Select mode / 选择模式 [1]: " MODE_INPUT
        case "${MODE_INPUT:-1}" in
            2) XHTTP_MODE="stream-up" ;;
            3) XHTTP_MODE="stream-down" ;;
            4) XHTTP_MODE="stream-one" ;;
            *) XHTTP_MODE="auto" ;;
        esac
        
        read -p "XHTTP path / XHTTP 路径 [/]: " PATH_INPUT
        XHTTP_PATH=${PATH_INPUT:-/}
        # Auto-prepend / if missing
        if [[ "$XHTTP_PATH" != /* ]]; then
            XHTTP_PATH="/$XHTTP_PATH"
        fi
        
        read -p "XHTTP host / XHTTP 域名 (Optional/可选) []: " HOST_INPUT
        XHTTP_HOST=${HOST_INPUT}

        echo -e "${GREEN}✓ XHTTP enabled / XHTTP 已启用${NC}"
        echo "  Mode / 模式: $XHTTP_MODE"
        echo "  Path / 路径: $XHTTP_PATH"
        echo "  Host / 域名: ${XHTTP_HOST:-*(Any)}"
    else
        echo -e "${GREEN}✓ Using TCP (default) / 使用 TCP (默认)${NC}"
    fi
fi

# Create server configuration with conditional XHTTP
# Build XHTTP settings if enabled
if [ "$ENABLE_XHTTP" = "y" ]; then
    XHTTP_SETTINGS=",
        \"xhttpSettings\": {
          \"mode\": \"$XHTTP_MODE\",
          \"path\": \"$XHTTP_PATH\",
          \"host\": \"$XHTTP_HOST\"
        }"
else
    XHTTP_SETTINGS=""
fi

cat > config.json << EOF
{
  "log": {
    "loglevel": "info"
  },
  "inbounds": [
    {
      "listen": "0.0.0.0",
      "port": $PORT,
      "protocol": "vless",
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
        "network": "$NETWORK_TYPE",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "$DEST",
          "xver": 0,
          "serverNames": [
            "$DOMAIN",
            "*.$DOMAIN"
          ],
          "privateKey": "$PRIVATE_KEY",
          "publicKey": "$PUBLIC_KEY",
          "shortIds": ["$SHORT_ID"],
          "fingerprint": "chrome"
        }$XHTTP_SETTINGS
      }
    }
  ],
  "outbounds": [{
    "protocol": "freedom",
    "tag": "direct"
  }],
  "routing": {
    "rules": []
  }
}
EOF

# Create client configuration
cat > client-config.json << EOF
{
  "log": {"loglevel": "info"},
  "inbounds": [{
    "port": 1080,
    "listen": "127.0.0.1",
    "protocol": "socks",
    "settings": {"udp": true}
  }],
  "outbounds": [{
    "protocol": "vless",
    "settings": {
      "vnext": [{
        "address": "$SERVER_IP",
        "port": $PORT,
        "users": [{
          "id": "$CLIENT_UUID",
          "encryption": "none",
          "flow": ""
        }]
      }]
    },
    "streamSettings": {
      "network": "tcp",
      "security": "reality",
      "realitySettings": {
        "show": false,
        "fingerprint": "chrome",
        "serverName": "$DOMAIN",
        "publicKey": "$PUBLIC_KEY",
        "shortId": "$SHORT_ID",
        "spiderX": "/"
      }
    }
  }]
}
EOF

# Set permissions
echo -e "${YELLOW}Setting permissions... / 设置权限...${NC}"
chown -R nobody:nogroup $INSTALL_DIR
chmod 755 $INSTALL_DIR
chmod 644 $INSTALL_DIR/config.json
chmod 755 $INSTALL_DIR/vless-server

# Install systemd service
echo -e "${YELLOW}[5/6] Installing systemd service... / 安装 systemd 服务...${NC}"

cat > /etc/systemd/system/xray-lite.service << EOF
[Unit]
Description=Xray-Lite VLESS Reality Server
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
Group=root
Environment=RUST_LOG=debug
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/vless-server --config $INSTALL_DIR/config.json
Restart=on-failure
RestartSec=10s

LimitNOFILE=1000000
LimitNPROC=512

StandardOutput=journal
StandardError=journal
SyslogIdentifier=xray-lite

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable xray-lite
echo -e "${GREEN}✓ Service installed / 服务已安装${NC}"
echo ""

# Configure firewall
echo -e "${YELLOW}[6/6] Configuring firewall... / 配置防火墙...${NC}"
# Ensure PORT is numeric again just in case
if [[ ! "$PORT" =~ ^[0-9]+$ ]]; then
    PORT=443
fi

if command -v ufw &> /dev/null; then
    if ufw status | grep -q "Status: active"; then
        ufw allow $PORT/tcp
        echo -e "${GREEN}✓ Firewall configured (ufw) / 防火墙已配置 (ufw)${NC}"
    else
        echo -e "${YELLOW}⚠ ufw is installed but not active / ufw 已安装但未启用${NC}"
    fi
elif command -v firewall-cmd &> /dev/null; then
    firewall-cmd --permanent --add-port=${PORT}/tcp
    firewall-cmd --reload
    echo -e "${GREEN}✓ Firewall configured (firewalld) / 防火墙已配置 (firewalld)${NC}"
else
    echo -e "${YELLOW}⚠ No firewall detected, please open port $PORT manually${NC}"
    echo -e "${YELLOW}⚠ 未检测到防火墙，请手动开放端口 $PORT${NC}"
fi
echo ""

# Check port availability
if lsof -i:$PORT -t >/dev/null 2>&1 ; then
    echo "Port $PORT is in use, attempting to clean up... / 端口 $PORT 被占用，尝试清理..."
    systemctl stop xray-lite >/dev/null 2>&1 || true
    pkill -f vless-server || true
    sleep 2
fi

if lsof -i:$PORT -t >/dev/null 2>&1 ; then
    echo -e "${RED}Error: Port $PORT is already in use! / 错误: 端口 $PORT 已被占用!${NC}"
    exit 1
fi
if ss -tuln | grep -q ":$PORT " ; then
    echo -e "${RED}Error: Port $PORT is already in use! / 错误: 端口 $PORT 已被占用!${NC}"
    exit 1
fi

# Start service
echo -e "${YELLOW}Starting Xray-Lite service... / 启动 Xray-Lite 服务...${NC}"
systemctl start xray-lite
sleep 2

if systemctl is-active --quiet xray-lite; then
    echo -e "${GREEN}✓ Service started successfully / 服务启动成功${NC}"
else
    echo -e "${RED}✗ Service failed to start / 服务启动失败${NC}"
    echo -e "${YELLOW}=== Error Logs / 错误日志 ===${NC}"
    journalctl -u xray-lite -n 20 --no-pager
    echo -e "${YELLOW}=============================${NC}"
    exit 1
fi
echo ""

# Display summary
echo -e "${GREEN}=========================================${NC}"
echo -e "${GREEN}  Installation Complete! / 安装完成！${NC}"
echo -e "${GREEN}=========================================${NC}"
echo ""
echo -e "${BLUE}Server Information / 服务器信息:${NC}"
echo "  IP: $SERVER_IP"
echo "  Port / 端口: $PORT"
echo "  UUID: $CLIENT_UUID"
echo "  Public Key / 公钥: $PUBLIC_KEY"
echo "  Short ID / 短 ID: $SHORT_ID"
echo ""
echo -e "${BLUE}Client Configuration / 客户端配置:${NC}"
echo "  Configuration file / 配置文件: $INSTALL_DIR/client-config.json"
echo "  Download / 下载: scp root@$SERVER_IP:$INSTALL_DIR/client-config.json ."
echo ""
echo -e "${BLUE}Service Management / 服务管理:${NC}"
echo "  Start / 启动:   systemctl start xray-lite"
echo "  Stop / 停止:    systemctl stop xray-lite"
echo "  Restart / 重启: systemctl restart xray-lite"
echo "  Status / 状态:  systemctl status xray-lite"
echo "  Logs / 日志:    journalctl -u xray-lite -f"
echo ""
echo -e "${BLUE}Uninstall / 卸载:${NC}"
echo "  systemctl stop xray-lite"
echo "  systemctl disable xray-lite"
echo "  rm -rf $INSTALL_DIR"
echo "  rm /etc/systemd/system/xray-lite.service"
echo ""
echo -e "${YELLOW}Next Steps / 下一步:${NC}"
echo "  1. Download client configuration / 下载客户端配置"
echo "  2. Import into Xray client / 导入到 Xray 客户端"
echo "  3. Connect and enjoy! / 连接并享受！"
echo ""
