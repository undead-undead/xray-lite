#!/bin/bash

# 发布助手脚本 (v0.1.1)
set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "========================================="
echo "  GitHub Release 发布助手 (v0.1.1)"
echo "========================================="
echo ""

# 1. 下载 gh 二进制文件 (如果不存在)
if [ ! -f "./gh" ]; then
    echo -e "${YELLOW}正在下载 GitHub CLI (gh)...${NC}"
    wget -q https://github.com/cli/cli/releases/download/v2.40.1/gh_2.40.1_linux_amd64.tar.gz -O gh.tar.gz
    tar -xzf gh.tar.gz
    cp gh_2.40.1_linux_amd64/bin/gh .
    chmod +x gh
    rm gh.tar.gz
    rm -rf gh_2.40.1_linux_amd64
    echo -e "${GREEN}gh 工具下载完成！${NC}"
fi

# 2. 登录检查
echo -e "${YELLOW}检查登录状态...${NC}"
if ! ./gh auth status &> /dev/null; then
    echo "请按回车键开始登录 (选择 GitHub.com -> HTTPS -> Login with web browser)"
    read -r
    ./gh auth login
fi

# 3. 创建 Release
VERSION="v0.1.11"
FILE="release/xray-lite-x86_64-unknown-linux-gnu.tar.gz"

if [ ! -f "$FILE" ]; then
    echo "错误：找不到二进制文件 $FILE"
    exit 1
fi

echo -e "正在发布 Release $VERSION ..."

# 创建 Release 并上传文件
if ./gh release create "$VERSION" "$FILE" --title "$VERSION - Native Reality Implementation" --notes "Rewrote Reality protocol with native Rust TLS 1.3 stack. Fixed decryption issues."; then
    echo -e "${GREEN}发布成功！${NC}"
    echo "发布地址: https://github.com/undead-undead/xray-lite/releases/tag/$VERSION"
    echo ""
    echo "🎉 请通知用户重新运行安装脚本升级到 v0.1.1"
else
    echo "发布失败，请检查上方错误信息。"
fi
