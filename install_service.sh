#!/bin/bash

# systemd Service Installation Script
# systemd 服务安装脚本

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "========================================="
echo "Install systemd Service / 安装 systemd 服务"
echo "========================================="
echo ""

# Check if running as root / 检查是否为 root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Please run this script with root privileges / 请使用 root 权限运行此脚本${NC}"
    echo "sudo ./install_service.sh"
    exit 1
fi

# Create installation directory / 创建安装目录
echo -e "${YELLOW}[1/5] Creating installation directory... / 创建安装目录...${NC}"
mkdir -p /opt/xray-lite
echo -e "${GREEN}✓ Directory created / 目录已创建${NC}"
echo ""

# Copy files / 复制文件
echo -e "${YELLOW}[2/5] Copying files... / 复制文件...${NC}"
cp target/release/vless-server /opt/xray-lite/
cp config.json /opt/xray-lite/
chmod +x /opt/xray-lite/vless-server
echo -e "${GREEN}✓ Files copied / 文件已复制${NC}"
echo ""

# Set permissions / 设置权限
echo -e "${YELLOW}[3/5] Setting permissions... / 设置权限...${NC}"
chown -R nobody:nogroup /opt/xray-lite
chmod 600 /opt/xray-lite/config.json
echo -e "${GREEN}✓ Permissions set / 权限已设置${NC}"
echo ""

# Install systemd service / 安装 systemd 服务
echo -e "${YELLOW}[4/5] Installing systemd service... / 安装 systemd 服务...${NC}"

# Update service file with correct name / 更新服务文件名称
sed 's/vless-reality/xray-lite/g' vless-reality.service > /tmp/xray-lite.service
sed -i 's/vless-reality-xhttp/xray-lite/g' /tmp/xray-lite.service

cp /tmp/xray-lite.service /etc/systemd/system/
systemctl daemon-reload
echo -e "${GREEN}✓ Service installed / 服务已安装${NC}"
echo ""

# Enable and start service / 启用并启动服务
echo -e "${YELLOW}[5/5] Starting service... / 启动服务...${NC}"
systemctl enable xray-lite
systemctl start xray-lite
echo -e "${GREEN}✓ Service started / 服务已启动${NC}"
echo ""

# Display status / 显示状态
echo "========================================="
echo -e "${GREEN}Installation Complete! / 安装完成！${NC}"
echo "========================================="
echo ""
echo "Service Management Commands / 服务管理命令:"
echo "  Start / 启动: systemctl start xray-lite"
echo "  Stop / 停止: systemctl stop xray-lite"
echo "  Restart / 重启: systemctl restart xray-lite"
echo "  Status / 状态: systemctl status xray-lite"
echo "  Logs / 日志: journalctl -u xray-lite -f"
echo ""
echo "Current Status / 当前状态:"
systemctl status xray-lite --no-pager
echo ""
