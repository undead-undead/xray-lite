#!/bin/bash

echo "========================================="
echo "Reality 密钥验证工具"
echo "========================================="
echo ""

# 读取配置文件
CONFIG_FILE="/opt/xray-lite/config.json"

if [ ! -f "$CONFIG_FILE" ]; then
    CONFIG_FILE="./config.example.json"
fi

if [ ! -f "$CONFIG_FILE" ]; then
    echo "错误: 找不到配置文件"
    exit 1
fi

# 提取私钥
PRIVATE_KEY=$(grep -o '"privateKey": *"[^"]*"' "$CONFIG_FILE" | sed 's/"privateKey": *"\([^"]*\)"/\1/')

echo "当前服务器私钥:"
echo "$PRIVATE_KEY"
echo ""

# 使用 keygen 生成对应的公钥
echo "对应的公钥应该是:"
echo "(需要使用 keygen 工具从私钥计算)"
echo ""

echo "========================================="
echo "请确保客户端配置中的 publicKey 与此匹配"
echo "========================================="
