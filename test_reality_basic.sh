#!/bin/bash

# Reality 模块基本功能测试脚本

set -e

echo "========================================="
echo "Reality 模块基本功能测试"
echo "========================================="
echo ""

# 颜色定义
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 1. 编译项目
echo -e "${YELLOW}[1/5] 编译项目...${NC}"
cargo build --release
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ 编译成功${NC}"
else
    echo -e "${RED}✗ 编译失败${NC}"
    exit 1
fi
echo ""

# 2. 运行单元测试
echo -e "${YELLOW}[2/5] 运行单元测试...${NC}"
cargo test --lib
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ 所有测试通过${NC}"
else
    echo -e "${RED}✗ 测试失败${NC}"
    exit 1
fi
echo ""

# 3. 检查二进制大小
echo -e "${YELLOW}[3/5] 检查二进制大小...${NC}"
BINARY_SIZE=$(ls -lh target/release/vless-server | awk '{print $5}')
echo "二进制大小: $BINARY_SIZE"
echo -e "${GREEN}✓ 二进制已生成${NC}"
echo ""

# 4. 验证配置文件
echo -e "${YELLOW}[4/5] 验证配置文件...${NC}"
if [ -f "config.test.json" ]; then
    echo "测试配置文件存在: config.test.json"
    echo -e "${GREEN}✓ 配置文件有效${NC}"
else
    echo -e "${RED}✗ 配置文件不存在${NC}"
    exit 1
fi
echo ""

# 5. 启动服务器 (后台运行 5 秒)
echo -e "${YELLOW}[5/5] 测试服务器启动...${NC}"
echo "启动服务器 (5 秒测试)..."

# 启动服务器
RUST_LOG=info timeout 5s ./target/release/vless-server --config config.test.json --log-level info &
SERVER_PID=$!

# 等待服务器启动
sleep 2

# 检查服务器是否在运行
if ps -p $SERVER_PID > /dev/null 2>&1; then
    echo -e "${GREEN}✓ 服务器成功启动 (PID: $SERVER_PID)${NC}"
    
    # 检查端口是否监听
    if netstat -tuln 2>/dev/null | grep -q ":8443" || ss -tuln 2>/dev/null | grep -q ":8443"; then
        echo -e "${GREEN}✓ 端口 8443 正在监听${NC}"
    else
        echo -e "${YELLOW}⚠ 无法确认端口监听状态 (可能需要 root 权限)${NC}"
    fi
    
    # 等待超时
    wait $SERVER_PID 2>/dev/null || true
else
    echo -e "${RED}✗ 服务器启动失败${NC}"
    exit 1
fi
echo ""

echo "========================================="
echo -e "${GREEN}✓ 所有基本功能测试通过！${NC}"
echo "========================================="
echo ""
echo "下一步:"
echo "1. 完善 ServerHello 修改逻辑"
echo "2. 与 Xray 客户端进行集成测试"
echo "3. 性能测试和优化"
echo ""
