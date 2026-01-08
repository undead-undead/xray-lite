#!/bin/bash

echo "=========================================="
echo "  创建 GitHub 仓库并上传代码"
echo "=========================================="
echo ""
echo "步骤 1: 在浏览器中打开以下链接创建仓库"
echo ""
echo "  https://github.com/new"
echo ""
echo "步骤 2: 填写以下信息"
echo ""
echo "  Repository name: xray-lite"
echo "  Description: Lightweight Xray implementation in Rust with Reality and XHTTP support"
echo "  Visibility: Public"
echo "  不要勾选任何初始化选项"
echo ""
echo "步骤 3: 点击 'Create repository'"
echo ""
echo "步骤 4: 创建完成后，按回车继续..."
read -p ""

echo ""
echo "正在推送代码到 GitHub..."
echo ""

cd /home/biubiuboy/xray-lite

# 推送代码
if git push -u origin main; then
    echo ""
    echo "=========================================="
    echo "  ✓ 上传成功！"
    echo "=========================================="
    echo ""
    echo "你的仓库地址:"
    echo "  https://github.com/undead-undead/xray-lite"
    echo ""
    echo "建议添加以下 Topics:"
    echo "  rust, xray, proxy, reality, http2, grpc"
    echo ""
else
    echo ""
    echo "上传失败，请检查错误信息"
fi
