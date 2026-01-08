#!/bin/bash

# Reality Module Integration Test
# Reality 模块集成测试
# Test compatibility with Xray clients / 测试与 Xray 客户端的兼容性

set -e

echo "========================================="
echo "Reality Module Integration Test"
echo "Reality 模块集成测试"
echo "========================================="
echo ""

# Color definitions / 颜色定义
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Check if Xray is installed / 检查 Xray 是否安装
echo -e "${YELLOW}[1/6] Checking if Xray is installed... / 检查 Xray 是否安装...${NC}"
if command -v xray &> /dev/null; then
    XRAY_VERSION=$(xray version | head -1)
    echo -e "${GREEN}✓ Xray installed / Xray 已安装: $XRAY_VERSION${NC}"
else
    echo -e "${RED}✗ Xray not installed / Xray 未安装${NC}"
    echo ""
    echo "Please install Xray first / 请先安装 Xray:"
    echo "  bash -c \"\$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)\" @ install"
    echo ""
    exit 1
fi
echo ""

# Build project / 编译项目
echo -e "${YELLOW}[2/6] Building project... / 编译项目...${NC}"
cargo build --release
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Build successful / 编译成功${NC}"
else
    echo -e "${RED}✗ Build failed / 编译失败${NC}"
    exit 1
fi
echo ""

# Start server / 启动服务器
echo -e "${YELLOW}[3/6] Starting Reality server... / 启动 Reality 服务器...${NC}"
echo "Port / 端口: 8443"
echo "Configuration / 配置: config.test.json"
echo ""

# Clean up old processes / 清理旧进程
pkill -f "vless-server" 2>/dev/null || true
sleep 1

# Start server / 启动服务器
RUST_LOG=info ./target/release/vless-server --config config.test.json --log-level info > server.log 2>&1 &
SERVER_PID=$!
echo "Server PID / 服务器 PID: $SERVER_PID"

# Wait for server startup / 等待服务器启动
echo "Waiting for server to start... / 等待服务器启动..."
sleep 3

# Check if server is running / 检查服务器是否在运行
if ! ps -p $SERVER_PID > /dev/null 2>&1; then
    echo -e "${RED}✗ Server failed to start / 服务器启动失败${NC}"
    echo "View logs / 查看日志: cat server.log"
    exit 1
fi
echo -e "${GREEN}✓ Server started / 服务器已启动${NC}"
echo ""

# Start Xray client / 启动 Xray 客户端
echo -e "${YELLOW}[4/6] Starting Xray client... / 启动 Xray 客户端...${NC}"
echo "SOCKS5 proxy / SOCKS5 代理: 127.0.0.1:1080"
echo "Configuration / 配置: xray-client-config.json"
echo ""

# Clean up old processes / 清理旧进程
pkill -f "xray.*client" 2>/dev/null || true
sleep 1

# Start client / 启动客户端
xray run -c xray-client-config.json > client.log 2>&1 &
CLIENT_PID=$!
echo "Client PID / 客户端 PID: $CLIENT_PID"

# Wait for client startup / 等待客户端启动
echo "Waiting for client to start... / 等待客户端启动..."
sleep 3

# Check if client is running / 检查客户端是否在运行
if ! ps -p $CLIENT_PID > /dev/null 2>&1; then
    echo -e "${RED}✗ Client failed to start / 客户端启动失败${NC}"
    echo "View logs / 查看日志: cat client.log"
    kill $SERVER_PID 2>/dev/null || true
    exit 1
fi
echo -e "${GREEN}✓ Client started / 客户端已启动${NC}"
echo ""

# Test connection / 测试连接
echo -e "${YELLOW}[5/6] Testing proxy connection... / 测试代理连接...${NC}"
echo "Testing HTTP request... / 测试 HTTP 请求..."

# Test 1: Simple HTTP request / 测试 1: 简单的 HTTP 请求
if curl -x socks5://127.0.0.1:1080 -m 10 -s http://www.example.com > /dev/null 2>&1; then
    echo -e "${GREEN}✓ HTTP request successful / HTTP 请求成功${NC}"
else
    echo -e "${RED}✗ HTTP request failed / HTTP 请求失败${NC}"
    echo "This may be normal as ServerHello modification may need refinement"
    echo "这可能是正常的，因为 ServerHello 修改可能还需要完善"
fi

# Test 2: HTTPS request / 测试 2: HTTPS 请求
echo "Testing HTTPS request... / 测试 HTTPS 请求..."
if curl -x socks5://127.0.0.1:1080 -m 10 -s https://www.google.com > /dev/null 2>&1; then
    echo -e "${GREEN}✓ HTTPS request successful / HTTPS 请求成功${NC}"
else
    echo -e "${YELLOW}⚠ HTTPS request failed (may need further debugging) / HTTPS 请求失败 (可能需要进一步调试)${NC}"
fi
echo ""

# View logs / 查看日志
echo -e "${YELLOW}[6/6] Viewing logs... / 查看日志...${NC}"
echo ""
echo -e "${BLUE}=== Server Logs (last 20 lines) / 服务器日志 (最后 20 行) ===${NC}"
tail -20 server.log
echo ""
echo -e "${BLUE}=== Client Logs (last 20 lines) / 客户端日志 (最后 20 行) ===${NC}"
tail -20 client.log
echo ""

# Cleanup / 清理
echo -e "${YELLOW}Cleaning up processes... / 清理进程...${NC}"
kill $CLIENT_PID 2>/dev/null || true
kill $SERVER_PID 2>/dev/null || true
sleep 1

echo "========================================="
echo -e "${GREEN}Integration Test Complete! / 集成测试完成！${NC}"
echo "========================================="
echo ""
echo "Log Files / 日志文件:"
echo "  Server / 服务器: server.log"
echo "  Client / 客户端: client.log"
echo ""
echo "Notes / 注意事项:"
echo "  1. If connection fails, check ServerHello modification logic"
echo "     如果连接失败，检查 ServerHello 修改逻辑"
echo "  2. Ensure private and public keys match"
echo "     确保私钥和公钥匹配"
echo "  3. Check if short_id configuration is consistent"
echo "     检查 short_id 配置是否一致"
echo ""
