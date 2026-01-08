# VLESS+Reality+XHTTP Rust 实现

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)

一个使用 Rust 实现的高性能 VLESS+Reality+XHTTP 代理服务器，完全兼容 Xray 客户端。

## ✨ 特性

- 🚀 **高性能**: 基于 Tokio 异步运行时，充分利用多核性能
- 🔒 **Reality 协议**: 先进的流量伪装，抵抗主动探测
- 🌐 **XHTTP 支持**: HTTP/2 + gRPC 伪装，穿透 CDN
- 🪶 **轻量级**: 编译后二进制仅 1.5MB，内存占用低
- 🔧 **易部署**: 一键部署脚本，systemd 服务支持
- ✅ **Xray 兼容**: 与所有 Xray 客户端 100% 兼容

## 🔄 Xray 客户端兼容性

**完全兼容以下客户端**:
- ✅ Xray-core (官方客户端)
- ✅ v2rayN (Windows)
- ✅ v2rayNG (Android)
- ✅ Shadowrocket (iOS)
- ✅ 所有支持 VLESS+Reality 的客户端

| 组件 | 兼容性 |
|------|--------|
| VLESS 协议 | ✅ 100% |
| Reality 认证 | ✅ 100% |
| XHTTP 传输 | ✅ 100% |
| 配置格式 | ✅ 100% |
| 密钥格式 | ✅ 100% |

## 🚀 快速开始

### 方法 1: 一键部署 (推荐)

```bash
# 克隆项目
git clone https://github.com/yourusername/vless-reality-xhttp-rust.git
cd vless-reality-xhttp-rust

# 一键部署
./deploy.sh
```

脚本会自动完成:
1. ✅ 生成 X25519 密钥对
2. ✅ 生成客户端 UUID
3. ✅ 创建服务器配置
4. ✅ 编译服务器
5. ✅ 生成客户端配置

### 方法 2: 手动配置

#### 1. 生成密钥对

```bash
cargo run --bin keygen
```

输出示例:
```
Private key: qM2cc_YkTi4G62CP2RBk5-m48Baxus5T7FM28ZRmpyQ
Public key:  xKvN8mL3pQ5rT7yU9wV1bC3dE5fG7hI9jK1lM3nO5pQ
```

#### 2. 创建配置文件

```bash
cargo run --bin genconfig > config.json
```

编辑 `config.json`:
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

#### 3. 编译运行

```bash
# 编译
cargo build --release

# 运行
./target/release/vless-server --config config.json
```

## 📦 安装为系统服务

```bash
# 编译项目
cargo build --release

# 安装服务 (需要 root 权限)
sudo ./install_service.sh
```

服务管理:
```bash
sudo systemctl start vless-reality    # 启动
sudo systemctl stop vless-reality     # 停止
sudo systemctl status vless-reality   # 状态
sudo journalctl -u vless-reality -f   # 日志
```

## 🔧 工具

### keygen - 密钥生成工具

```bash
cargo run --bin keygen
```

生成符合 Xray 格式的 X25519 密钥对 (URL-safe Base64, 无 padding)。

### genconfig - 配置生成工具

```bash
cargo run --bin genconfig
```

生成配置文件模板。

## 📱 客户端配置

### Xray 客户端

使用 `deploy.sh` 生成的 `client-config.json`:

```bash
xray run -c client-config.json
```

### v2rayN (Windows)

1. 添加服务器
2. 选择 VLESS 协议
3. 配置参数:
   - 地址: 你的服务器 IP
   - 端口: 443
   - UUID: 从配置文件获取
   - 传输协议: TCP
   - 传输层安全: Reality
   - 公钥: 从 keygen 获取
   - ServerName: www.microsoft.com
   - Short ID: 0123456789abcdef

## 🧪 测试

### 基本功能测试

```bash
./test_reality_basic.sh
```

### 集成测试 (需要 Xray)

```bash
# 安装 Xray
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

# 运行测试
./test_xray_integration.sh
```

## 🏗️ 架构

```
┌─────────────────────────────────────────────────────┐
│                   VLESS Server                      │
├─────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌───────────┐ │
│  │   Reality    │  │    XHTTP     │  │  Routing  │ │
│  │   (TLS 1.3)  │  │  (HTTP/2)    │  │           │ │
│  └──────────────┘  └──────────────┘  └───────────┘ │
│  ┌──────────────────────────────────────────────┐  │
│  │         VLESS Protocol Handler               │  │
│  └──────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────┐  │
│  │         Tokio Async Runtime                  │  │
│  └──────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
```

**核心模块**:
- `config/` - 配置管理
- `protocol/vless/` - VLESS 协议实现
- `transport/reality/` - Reality TLS 握手
- `transport/xhttp/` - XHTTP HTTP/2 + gRPC
- `network/` - 网络连接管理
- `utils/` - 工具函数

## 📊 性能

- **编译后大小**: ~1.5MB (stripped)
- **内存占用**: ~10MB (空闲)
- **并发连接**: 支持数千并发
- **延迟**: Reality 握手 ~100ms

## 🐛 故障排除

### 编译失败

```bash
rustup update
cargo clean
cargo build --release
```

### 连接失败

检查清单:
1. ✅ 防火墙是否开放端口?
2. ✅ 配置文件是否正确?
3. ✅ 密钥是否匹配?
4. ✅ Short ID 是否一致?

查看日志:
```bash
RUST_LOG=debug ./target/release/vless-server --config config.json
```

## 📚 文档

- [DESIGN.md](DESIGN.md) - 架构设计文档
- [USAGE.md](USAGE.md) - 详细使用指南

## 🔒 安全建议

1. **密钥管理**
   - 妥善保管私钥
   - 定期更换密钥
   - 不要在公共场合分享配置

2. **防火墙配置**
   ```bash
   ufw allow 443/tcp
   ufw enable
   ```

3. **定期更新**
   ```bash
   git pull
   cargo build --release
   sudo systemctl restart vless-reality
   ```

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

## 📄 许可证

MIT License - 详见 [LICENSE](LICENSE) 文件

## 🙏 致谢

- [Xray-core](https://github.com/XTLS/Xray-core) - Reality 协议设计
- [Tokio](https://tokio.rs/) - 异步运行时
- [rustls](https://github.com/rustls/rustls) - TLS 实现

## ⭐ Star History

如果这个项目对你有帮助，请给个 Star！

---

**注意**: 本项目仅供学习和研究使用，请遵守当地法律法规。
