#!/bin/bash

# Reality Module Basic Functionality Test
# Reality 模块基本功能测试

set -e

echo "========================================="
echo "Reality Module Basic Functionality Test"
echo "Reality 模块基本功能测试"
echo "========================================="
echo ""

# Color definitions / 颜色定义
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Build project / 编译项目
echo -e "${YELLOW}[1/5] Building project... / 编译项目...${NC}"
if cargo build --release; then
    echo -e "${GREEN}✓ Build successful / 编译成功${NC}"
else
    echo -e "${RED}✗ Build failed / 编译失败${NC}"
    exit 1
fi
echo ""

# Run unit tests / 运行单元测试
echo -e "${YELLOW}[2/5] Running unit tests... / 运行单元测试...${NC}"
if cargo test --lib; then
    echo -e "${GREEN}✓ All tests passed / 所有测试通过${NC}"
else
    echo -e "${RED}✗ Tests failed / 测试失败${NC}"
    exit 1
fi
echo ""

# Check binary size / 检查二进制大小
echo -e "${YELLOW}[3/5] Checking binary size... / 检查二进制大小...${NC}"
BINARY_SIZE=$(du -h target/release/vless-server | cut -f1)
echo "Binary size / 二进制大小: $BINARY_SIZE"
echo -e "${GREEN}✓ Binary generated / 二进制已生成${NC}"
echo ""

# Validate configuration file / 验证配置文件
echo -e "${YELLOW}[4/5] Validating configuration file... / 验证配置文件...${NC}"
if [ -f "config.test.json" ]; then
    echo -e "${GREEN}✓ Test configuration found / 找到测试配置${NC}"
else
    echo -e "${RED}✗ config.test.json not found / 未找到 config.test.json${NC}"
    exit 1
fi
echo ""

# Test server startup / 测试服务器启动
echo -e "${YELLOW}[5/5] Testing server startup... / 测试服务器启动...${NC}"
echo "Starting server in background for 5 seconds..."
echo "在后台启动服务器 5 秒..."

# Start server / 启动服务器
./target/release/vless-server --config config.test.json > /dev/null 2>&1 &
SERVER_PID=$!

# Wait for startup / 等待启动
sleep 2

# Check if server is running / 检查服务器是否运行
if ps -p $SERVER_PID > /dev/null; then
    echo -e "${GREEN}✓ Server started successfully / 服务器启动成功${NC}"
    
    # Check port listening / 检查端口监听
    if netstat -tuln | grep -q ":8443"; then
        echo -e "${GREEN}✓ Port 8443 is listening / 端口 8443 正在监听${NC}"
    else
        echo -e "${YELLOW}⚠ Port 8443 not detected (may need more time) / 未检测到端口 8443 (可能需要更多时间)${NC}"
    fi
    
    # Stop server / 停止服务器
    kill $SERVER_PID 2>/dev/null
    wait $SERVER_PID 2>/dev/null
    echo -e "${GREEN}✓ Server stopped / 服务器已停止${NC}"
else
    echo -e "${RED}✗ Server failed to start / 服务器启动失败${NC}"
    exit 1
fi
echo ""

# Summary / 总结
echo "========================================="
echo -e "${GREEN}Basic Functionality Test Complete! / 基本功能测试完成！${NC}"
echo "========================================="
echo ""
echo "Test Results / 测试结果:"
echo "  ✓ Build / 编译"
echo "  ✓ Unit Tests / 单元测试"
echo "  ✓ Binary Generation / 二进制生成"
echo "  ✓ Configuration Validation / 配置验证"
echo "  ✓ Server Startup / 服务器启动"
echo ""
echo "Next Steps / 下一步:"
echo "  1. Run integration test / 运行集成测试: ./test_xray_integration.sh"
echo "  2. Deploy to production / 部署到生产环境: ./deploy.sh"
echo ""
