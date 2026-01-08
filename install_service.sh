#!/bin/bash

# systemd 服务安装脚本

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "========================================="
echo "安装 systemd 服务"
echo "========================================="
echo ""

# 检查是否为 root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}请使用 root 权限运行此脚本${NC}"
    echo "sudo ./install_service.sh"
    exit 1
fi

# 创建安装目录
echo -e "${YELLOW}[1/5] 创建安装目录...${NC}"
mkdir -p /opt/vless-reality-xhttp
echo -e "${GREEN}✓ 目录已创建${NC}"
echo ""

# 复制文件
echo -e "${YELLOW}[2/5] 复制文件...${NC}"
cp target/release/vless-server /opt/vless-reality-xhttp/
cp config.json /opt/vless-reality-xhttp/
chmod +x /opt/vless-reality-xhttp/vless-server
echo -e "${GREEN}✓ 文件已复制${NC}"
echo ""

# 设置权限
echo -e "${YELLOW}[3/5] 设置权限...${NC}"
chown -R nobody:nogroup /opt/vless-reality-xhttp
chmod 600 /opt/vless-reality-xhttp/config.json
echo -e "${GREEN}✓ 权限已设置${NC}"
echo ""

# 安装 systemd 服务
echo -e "${YELLOW}[4/5] 安装 systemd 服务...${NC}"
cp vless-reality.service /etc/systemd/system/
systemctl daemon-reload
echo -e "${GREEN}✓ 服务已安装${NC}"
echo ""

# 启用并启动服务
echo -e "${YELLOW}[5/5] 启动服务...${NC}"
systemctl enable vless-reality
systemctl start vless-reality
echo -e "${GREEN}✓ 服务已启动${NC}"
echo ""

# 显示状态
echo "========================================="
echo -e "${GREEN}安装完成！${NC}"
echo "========================================="
echo ""
echo "服务管理命令:"
echo "  启动: systemctl start vless-reality"
echo "  停止: systemctl stop vless-reality"
echo "  重启: systemctl restart vless-reality"
echo "  状态: systemctl status vless-reality"
echo "  日志: journalctl -u vless-reality -f"
echo ""
echo "当前状态:"
systemctl status vless-reality --no-pager
echo ""
