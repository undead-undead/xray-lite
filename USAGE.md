# VLESS+Reality+XHTTP Rust 实现 - 使用指南

## 🚀 快速开始

### 方法 1: 一键部署 (推荐)

```bash
# 克隆项目
git clone https://github.com/yourusername/vless-reality-xhttp-rust.git
cd vless-reality-xhttp-rust

# 运行一键部署脚本
./deploy.sh
```

脚本会自动:
1. ✅ 生成 X25519 密钥对
2. ✅ 生成客户端 UUID
3. ✅ 创建服务器配置
4. ✅ 编译服务器
5. ✅ 生成客户端配置

### 方法 2: 手动配置

#### 步骤 1: 生成密钥对

```bash
# 编译并运行密钥生成工具
cargo run --bin keygen

# 输出示例:
# Private key: gKFubRNJ7lRLrjI0T5Jz9Q3WvYvL8B5mN2cD1xF4pHk
# Public key: xKvN8mL3pQ5rT7yU9wV1bC3dE5fG7hI9jK1lM3nO5pQ
```

#### 步骤 2: 生成配置文件

```bash
# 生成配置模板
cargo run --bin genconfig > config.json

# 或手动创建 config.json
```

#### 步骤 3: 编辑配置

```json
{
  "inbounds": [{
    "protocol": "vless",
    "port": 443,
    "settings": {
      "clients": [{
        "id": "YOUR-UUID-HERE"
      }]
    },
    "streamSettings": {
      "security": "reality",
      "realitySettings": {
        "dest": "www.microsoft.com:443",
        "serverNames": ["www.microsoft.com"],
        "privateKey": "YOUR-PRIVATE-KEY-HERE",
        "shortIds": ["0123456789abcdef"]
      }
    }
  }]
}
```

#### 步骤 4: 编译运行

```bash
# 编译
cargo build --release

# 运行
./target/release/vless-server --config config.json
```

## 📦 安装为系统服务

### 使用 systemd (Linux)

```bash
# 编译项目
cargo build --release

# 安装服务 (需要 root 权限)
sudo ./install_service.sh
```

服务管理命令:
```bash
# 启动服务
sudo systemctl start vless-reality

# 停止服务
sudo systemctl stop vless-reality

# 重启服务
sudo systemctl restart vless-reality

# 查看状态
sudo systemctl status vless-reality

# 查看日志
sudo journalctl -u vless-reality -f
```

## 🔧 工具使用

### 1. 密钥生成工具 (keygen)

```bash
cargo run --bin keygen
```

生成符合 Xray 格式的 X25519 密钥对。

### 2. 配置生成工具 (genconfig)

```bash
cargo run --bin genconfig
```

生成配置文件模板。

### 3. 一键部署脚本 (deploy.sh)

```bash
./deploy.sh
```

自动完成所有配置和编译步骤。

## 📱 客户端配置

### Xray 客户端

使用 `deploy.sh` 生成的 `client-config.json`:

```bash
xray run -c client-config.json
```

### v2rayN (Windows)

1. 打开 v2rayN
2. 添加服务器
3. 选择 VLESS 协议
4. 配置参数:
   - 地址: 你的服务器 IP
   - 端口: 443
   - UUID: 从配置文件获取
   - 传输协议: TCP
   - 传输层安全: Reality
   - 公钥: 从 keygen 获取
   - ServerName: www.microsoft.com
   - Short ID: 0123456789abcdef

### v2rayNG (Android)

类似 v2rayN 的配置方式。

## 🧪 测试

### 基本功能测试

```bash
./test_reality_basic.sh
```

测试内容:
- 编译检查
- 单元测试
- 服务器启动
- 端口监听

### 集成测试 (需要 Xray)

```bash
# 安装 Xray
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

# 运行集成测试
./test_xray_integration.sh
```

### 手动测试

```bash
# 启动服务器
./target/release/vless-server --config config.json &

# 启动 Xray 客户端
xray run -c client-config.json &

# 测试连接
curl -x socks5://127.0.0.1:1080 https://www.google.com
```

## 🐛 故障排除

### 问题 1: 编译失败

```bash
# 更新 Rust
rustup update

# 清理并重新编译
cargo clean
cargo build --release
```

### 问题 2: 连接失败

检查清单:
1. ✅ 防火墙是否开放端口?
2. ✅ 配置文件是否正确?
3. ✅ 密钥是否匹配?
4. ✅ Short ID 是否一致?

查看日志:
```bash
# 启用详细日志
RUST_LOG=debug ./target/release/vless-server --config config.json

# 或查看 systemd 日志
sudo journalctl -u vless-reality -f
```

### 问题 3: 性能问题

```bash
# 使用 release 模式
cargo build --release

# 检查系统资源
htop

# 查看连接数
netstat -an | grep :443 | wc -l
```

## 📊 性能优化

### 编译优化

已在 `Cargo.toml` 中配置:
```toml
[profile.release]
opt-level = 3
lto = true
codegen-units = 1
strip = true
```

### 系统优化

```bash
# 增加文件描述符限制
ulimit -n 1000000

# 优化 TCP 参数
sysctl -w net.core.rmem_max=26214400
sysctl -w net.core.wmem_max=26214400
```

## 🔒 安全建议

1. **密钥管理**
   - 妥善保管私钥
   - 定期更换密钥
   - 不要在公共场合分享配置

2. **防火墙配置**
   ```bash
   # 只开放必要端口
   ufw allow 443/tcp
   ufw enable
   ```

3. **定期更新**
   ```bash
   git pull
   cargo build --release
   sudo systemctl restart vless-reality
   ```

## 📚 更多文档

- [DESIGN.md](DESIGN.md) - 架构设计
- [REALITY_IMPLEMENTATION.md](REALITY_IMPLEMENTATION.md) - Reality 实现
- [XRAY_COMPATIBILITY.md](XRAY_COMPATIBILITY.md) - Xray 兼容性
- [COMPLETE_IMPLEMENTATION.md](COMPLETE_IMPLEMENTATION.md) - 完整实现总结

## 🆘 获取帮助

- GitHub Issues: [提交问题](https://github.com/yourusername/vless-reality-xhttp-rust/issues)
- 查看日志: `sudo journalctl -u vless-reality -f`
- 详细日志: `RUST_LOG=debug cargo run`

## 📄 许可证

MIT License - 详见 [LICENSE](LICENSE) 文件
