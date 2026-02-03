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
VERSION="v0.6.0-xdp"
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

# Detect Kernel for XDP support / 检测内核支持 XDP
# Requirement: Kernel >= 5.4 and x86_64 (musl eBPF support on aarch64 is tricky)
KERNEL_VERSION=$(uname -r)
KERNEL_MAJOR=$(echo $KERNEL_VERSION | cut -d. -f1)
KERNEL_MINOR=$(echo $KERNEL_VERSION | cut -d. -f2)

SUPPORT_XDP=false

# Simple version check for >= 5.4
if [ "$KERNEL_MAJOR" -gt 5 ]; then
    SUPPORT_XDP=true
elif [ "$KERNEL_MAJOR" -eq 5 ] && [ "$KERNEL_MINOR" -ge 4 ]; then
    SUPPORT_XDP=true
fi

# Limit XDP to x86_64 for now
if [ "$BINARY_ARCH" != "x86_64" ]; then
    SUPPORT_XDP=false
fi

XDP_ARGS=""

if [ "$SUPPORT_XDP" = true ]; then
    echo -e "${GREEN}High-performance Kernel Detected / 检测到高性能内核: ${KERNEL_VERSION}${NC}"
    echo -e "${GREEN}Enabling XDP Firewall Mode (Anti-Probe) / 启用 XDP 防火墙模式 (抗探测)${NC}"
    # Use the XDP-enhanced binary
    # Find active interface for XDP
    DEFAULT_IFACE=$(ip route get 8.8.8.8 | grep -oP 'dev \K\S+')
    XDP_ARGS="--enable-xdp --xdp-iface ${DEFAULT_IFACE:-eth0}"
else
    echo -e "${YELLOW}Standard Kernel Detected / 检测到标准内核: ${KERNEL_VERSION}${NC}"
    echo -e "${YELLOW}Using Standard Mode (Compatibility) / 使用标准模式 (兼容模式)${NC}"
fi

# Use the static single binary for all cases (it contains XDP logic internally)
# 使用静态单一二进制 (内部包含 XDP 逻辑)
if [ "$BINARY_ARCH" = "amd64" ] || [ "$BINARY_ARCH" = "x86_64" ]; then
    if [ "$SUPPORT_XDP" = true ]; then
        XRAY_BINARY_NAME="vless-server-linux-x86_64-xdp"
    else
        XRAY_BINARY_NAME="vless-server-linux-x86_64"
    fi
else
    # Fallback for arm64 if we ever support it in static build
    XRAY_BINARY_NAME="vless-server-linux-${BINARY_ARCH}"
fi
echo ""

# Stop existing service / 停止现有服务
echo -e "${YELLOW}Checking for existing installation... / 检查现有安装...${NC}"
if systemctl is-active --quiet xray-lite; then
    echo "Stopping existing xray-lite service... / 停止现有 xray-lite 服务..."
    systemctl stop xray-lite >/dev/null 2>&1
    systemctl disable xray-lite >/dev/null 2>&1
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
# Download Static Binaries / 下载静态二进制文件
echo -e "${YELLOW}[2/6] Downloading Xray-Lite binaries... / 下载 Xray-Lite 二进制文件...${NC}"

XRAY_BINARY="${XRAY_BINARY_NAME}"

if [ "$BINARY_ARCH" = "amd64" ] || [ "$BINARY_ARCH" = "x86_64" ]; then
    KEYGEN_BINARY="keygen-linux-x86_64"
else
    KEYGEN_BINARY="keygen-linux-${BINARY_ARCH}"
fi

DOWNLOAD_PREFIX="https://github.com/${REPO}/releases/download/${VERSION}"
FALLBACK_PREFIX="https://github.com/${REPO}/releases/download/${VERSION}"

echo "Downloading vless-server..."
if curl -fsSL "${DOWNLOAD_PREFIX}/${XRAY_BINARY}" -o "vless-server"; then
    echo -e "${GREEN}✓ vless-server downloaded${NC}"
else
    echo -e "${RED}Failed to download vless-server${NC}"
    exit 1
fi

echo "Downloading keygen..."
if curl -fsSL "${DOWNLOAD_PREFIX}/${KEYGEN_BINARY}" -o "keygen"; then
    echo -e "${GREEN}✓ keygen downloaded${NC}"
else
    echo -e "${RED}Failed to download keygen${NC}"
    exit 1
fi

chmod +x vless-server keygen
echo -e "${GREEN}✓ Files prepared / 文件已准备就绪${NC}"
echo ""

# Generate configuration / 生成配置
echo -e "${YELLOW}[4/6] Generating configuration... / 生成配置...${NC}"

# Generate keys / 生成密钥
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
        XHTTP_MODE="auto"
        
        echo ""
        read -p "XHTTP path / XHTTP 路径 [/]: " PATH_INPUT
        XHTTP_PATH=${PATH_INPUT:-/}
        # Auto-prepend / if missing
        if [[ "$XHTTP_PATH" != /* ]]; then
            XHTTP_PATH="/$XHTTP_PATH"
        fi
        
        read -p "XHTTP host / XHTTP 域名 (Optional/可选) []: " HOST_INPUT
        XHTTP_HOST=${HOST_INPUT}

        echo -e "${GREEN}✓ XHTTP enabled / XHTTP 已启用${NC}"
        echo "  Mode: Intelligent Adaptive (Integrated) / 智能自适应"
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
Environment=RUST_LOG=info
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/vless-server --config $INSTALL_DIR/config.json ${XDP_ARGS}
Restart=on-failure
RestartSec=10s

LimitNOFILE=1000000
LimitNPROC=512

SyslogIdentifier=xray-lite
StandardOutput=null
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload >/dev/null 2>&1
systemctl enable xray-lite >/dev/null 2>&1
echo -e "${GREEN}✓ Service installed / 服务已安装${NC}"
echo ""

# Configure journald log rotation for xray-lite / 配置 journald 日志轮转
echo -e "${YELLOW}Configuring log rotation... / 配置日志轮转...${NC}"
mkdir -p /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/xray-lite.conf << EOF
# Xray-Lite journald log rotation configuration
# Xray-Lite journald 日志轮转配置
[Journal]
# Maximum disk usage for logs / 日志最大磁盘使用量
SystemMaxUse=50M
# Maximum size of individual log files / 单个日志文件最大大小
SystemMaxFileSize=10M
# Log retention time (7 days) / 日志保留时间（7天）
MaxRetentionSec=7day
# Compress logs older than 1 day / 压缩超过1天的日志
Compress=yes
EOF

# Restart journald to apply configuration / 重启 journald 应用配置
systemctl restart systemd-journald >/dev/null 2>&1
echo -e "${GREEN}✓ Log rotation configured (max 50MB, 7 days) / 日志轮转已配置 (最大 50MB, 7天)${NC}"
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
    firewall-cmd --permanent --add-port=${PORT}/tcp >/dev/null 2>&1
    firewall-cmd --reload >/dev/null 2>&1
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
