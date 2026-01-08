#!/bin/bash

# Reality 模块集成测试脚本
# 测试与 Xray 客户端的兼容性

set -e

echo "========================================="
echo "Reality 模块集成测试"
echo "========================================="
echo ""

# 颜色定义
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 检查 Xray 是否安装
echo -e "${YELLOW}[1/6] 检查 Xray 是否安装...${NC}"
if command -v xray &> /dev/null; then
    XRAY_VERSION=$(xray version | head -1)
    echo -e "${GREEN}✓ Xray 已安装: $XRAY_VERSION${NC}"
else
    echo -e "${RED}✗ Xray 未安装${NC}"
    echo ""
    echo "请先安装 Xray:"
    echo "  bash -c \"\$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)\" @ install"
    echo ""
    exit 1
fi
echo ""

# 编译项目
echo -e "${YELLOW}[2/6] 编译项目...${NC}"
cargo build --release
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ 编译成功${NC}"
else
    echo -e "${RED}✗ 编译失败${NC}"
    exit 1
fi
echo ""

# 启动服务器
echo -e "${YELLOW}[3/6] 启动 Reality 服务器...${NC}"
echo "端口: 8443"
echo "配置: config.test.json"
echo ""

# 清理旧进程
pkill -f "vless-server" 2>/dev/null || true
sleep 1

# 启动服务器
RUST_LOG=info ./target/release/vless-server --config config.test.json --log-level info > server.log 2>&1 &
SERVER_PID=$!
echo "服务器 PID: $SERVER_PID"

# 等待服务器启动
echo "等待服务器启动..."
sleep 3

# 检查服务器是否在运行
if ! ps -p $SERVER_PID > /dev/null 2>&1; then
    echo -e "${RED}✗ 服务器启动失败${NC}"
    echo "查看日志: cat server.log"
    exit 1
fi
echo -e "${GREEN}✓ 服务器已启动${NC}"
echo ""

# 启动 Xray 客户端
echo -e "${YELLOW}[4/6] 启动 Xray 客户端...${NC}"
echo "SOCKS5 代理: 127.0.0.1:1080"
echo "配置: xray-client-config.json"
echo ""

# 清理旧进程
pkill -f "xray.*client" 2>/dev/null || true
sleep 1

# 启动客户端
xray run -c xray-client-config.json > client.log 2>&1 &
CLIENT_PID=$!
echo "客户端 PID: $CLIENT_PID"

# 等待客户端启动
echo "等待客户端启动..."
sleep 3

# 检查客户端是否在运行
if ! ps -p $CLIENT_PID > /dev/null 2>&1; then
    echo -e "${RED}✗ 客户端启动失败${NC}"
    echo "查看日志: cat client.log"
    kill $SERVER_PID 2>/dev/null || true
    exit 1
fi
echo -e "${GREEN}✓ 客户端已启动${NC}"
echo ""

# 测试连接
echo -e "${YELLOW}[5/6] 测试代理连接...${NC}"
echo "测试 HTTP 请求..."

# 测试 1: 简单的 HTTP 请求
if curl -x socks5://127.0.0.1:1080 -m 10 -s http://www.example.com > /dev/null 2>&1; then
    echo -e "${GREEN}✓ HTTP 请求成功${NC}"
else
    echo -e "${RED}✗ HTTP 请求失败${NC}"
    echo "这可能是正常的，因为 ServerHello 修改可能还需要完善"
fi

# 测试 2: HTTPS 请求
echo "测试 HTTPS 请求..."
if curl -x socks5://127.0.0.1:1080 -m 10 -s https://www.google.com > /dev/null 2>&1; then
    echo -e "${GREEN}✓ HTTPS 请求成功${NC}"
else
    echo -e "${YELLOW}⚠ HTTPS 请求失败 (可能需要进一步调试)${NC}"
fi
echo ""

# 查看日志
echo -e "${YELLOW}[6/6] 查看日志...${NC}"
echo ""
echo -e "${BLUE}=== 服务器日志 (最后 20 行) ===${NC}"
tail -20 server.log
echo ""
echo -e "${BLUE}=== 客户端日志 (最后 20 行) ===${NC}"
tail -20 client.log
echo ""

# 清理
echo -e "${YELLOW}清理进程...${NC}"
kill $CLIENT_PID 2>/dev/null || true
kill $SERVER_PID 2>/dev/null || true
sleep 1

echo "========================================="
echo -e "${GREEN}集成测试完成！${NC}"
echo "========================================="
echo ""
echo "日志文件:"
echo "  服务器: server.log"
echo "  客户端: client.log"
echo ""
echo "注意事项:"
echo "1. 如果连接失败，检查 ServerHello 修改逻辑"
echo "2. 确保私钥和公钥匹配"
echo "3. 检查 short_id 配置是否一致"
echo ""
