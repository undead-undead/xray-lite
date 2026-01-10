# Xray-Lite

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)
[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-Support-orange?style=flat&logo=buy-me-a-coffee)](https://buymeacoffee.com/undeadundead)

**English** | [中文](#chinese-documentation)

A lightweight, high-performance VLESS + Reality proxy server implemented in pure Rust. Fully compatible with all Xray/V2Ray clients.

一个轻量级、高性能的纯 Rust 实现的 VLESS + Reality 代理服务器。完全兼容所有 Xray/V2Ray 客户端。

---

## ✨ Features / 特性

| Feature / 特性 | Status / 状态 | Description / 描述 |
|---------------|---------------|---------------------|
| **VLESS Protocol** | ✅ Stable | Full VLESS protocol support / 完整 VLESS 协议支持 |
| **Reality** | ✅ Stable | TLS 1.3 with dynamic certificate / TLS 1.3 动态证书 |
| **SNI Sniffing** | ✅ Stable | Auto-detect target domain / 自动嗅探目标域名 |
| **XHTTP** | 🚧 Coming Soon | HTTP/2 + gRPC transport / HTTP/2 + gRPC 传输层 |

### Why Xray-Lite? / 为什么选择 Xray-Lite？

- 🚀 **High Performance / 高性能**: Built on Tokio async runtime / 基于 Tokio 异步运行时
- 🪶 **Lightweight / 轻量级**: ~1.5MB binary, ~10MB RAM / 约 1.5MB 二进制文件，约 10MB 内存
- 🔒 **Secure / 安全**: Reality protocol resists active probing / Reality 协议抵抗主动探测
- ✅ **Compatible / 兼容**: Works with v2rayN, Shadowrocket, Passwall, etc. / 兼容 v2rayN、小火箭、Passwall 等

---

## 🚀 Quick Start / 快速开始

### One-Click Installation (Recommended) / 一键安装（推荐）

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/undead-undead/xray-lite/main/install.sh)
```

The script will: / 脚本将自动：
1. Download the latest binary / 下载最新二进制文件
2. Generate keys and UUID / 生成密钥和 UUID
3. Configure systemd service / 配置 systemd 服务
4. Start the server / 启动服务器
5. Display connection info / 显示连接信息

### Build from Source / 从源码构建

```bash
# Clone the repository / 克隆仓库
git clone https://github.com/undead-undead/xray-lite.git
cd xray-lite

# Build / 构建
cargo build --release

# Run / 运行
./target/release/vless-server --config config.json
```

---

## 📱 Client Configuration / 客户端配置

### Supported Clients / 支持的客户端

| Client / 客户端 | Platform / 平台 | Status / 状态 |
|-----------------|-----------------|---------------|
| v2rayN | Windows | ✅ Tested |
| v2rayNG | Android | ✅ Tested |
| Shadowrocket | iOS | ✅ Tested |
| Passwall | OpenWrt | ✅ Tested |
| Xray-core | CLI | ✅ Tested |

### Configuration Parameters / 配置参数

After installation, you will see: / 安装后会显示：

```
Server Information / 服务器信息:
  IP: YOUR_SERVER_IP
  Port / 端口: 443
  UUID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
  Public Key / 公钥: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
  Short ID / 短 ID: xxxxxxxxxxxxxxxx
```

### v2rayN Configuration / v2rayN 配置

| Field / 字段 | Value / 值 |
|--------------|------------|
| Address / 地址 | Your server IP / 服务器 IP |
| Port / 端口 | 443 |
| UUID | From installation output / 安装输出的 UUID |
| Flow / 流控 | **Leave empty / 留空** |
| Encryption / 加密 | none |
| Network / 传输协议 | tcp |
| Security / 传输层安全 | reality |
| SNI | www.microsoft.com |
| Public Key / 公钥 | From installation output / 安装输出的公钥 |
| Short ID / 短 ID | From installation output / 安装输出的短 ID |
| Fingerprint / 指纹 | chrome |

> ⚠️ **Important / 重要**: Flow must be empty! Do not use `xtls-rprx-vision`. / Flow 必须留空！不要使用 `xtls-rprx-vision`。

---

## ⚙️ Service Management / 服务管理

```bash
# Start / 启动
sudo systemctl start xray-lite

# Stop / 停止
sudo systemctl stop xray-lite

# Restart / 重启
sudo systemctl restart xray-lite

# Status / 状态
sudo systemctl status xray-lite

# Logs / 日志
sudo journalctl -u xray-lite -f
```

---

## 🔧 Configuration / 配置

### Example Configuration / 配置示例

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
        "privateKey": "YOUR-PRIVATE-KEY",
        "shortIds": ["0123456789abcdef"]
      }
    }
  }]
}
```

### Generate Keys / 生成密钥

```bash
# Generate X25519 key pair / 生成 X25519 密钥对
cargo run --bin keygen

# Output / 输出:
# Private key: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
# Public key:  xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

---

## 🏗️ Architecture / 架构

```
┌─────────────────────────────────────────────────────┐
│                    Xray-Lite                        │
├─────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌───────────┐ │
│  │   Reality    │  │ SNI Sniffer  │  │  XHTTP    │ │
│  │  (rustls)    │  │              │  │  (Soon)   │ │
│  └──────────────┘  └──────────────┘  └───────────┘ │
│  ┌──────────────────────────────────────────────┐  │
│  │         VLESS Protocol Handler               │  │
│  └──────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────┐  │
│  │         Tokio Async Runtime                  │  │
│  └──────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
```

---

## 🐛 Troubleshooting / 故障排除

### Connection Failed / 连接失败

1. **Check firewall / 检查防火墙**
   ```bash
   sudo ufw allow 443/tcp
   ```

2. **Check logs / 查看日志**
   ```bash
   sudo journalctl -u xray-lite -f
   ```

3. **Verify client config / 验证客户端配置**
   - Flow must be empty / Flow 必须为空
   - Public key must match / 公钥必须匹配
   - Short ID must match / 短 ID 必须匹配

### Build Failed / 编译失败

```bash
rustup update
cargo clean
cargo build --release
```

---

## 📄 License / 许可证

MIT License - See [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgments / 致谢

- [Xray-core](https://github.com/XTLS/Xray-core) - Reality protocol design / Reality 协议设计
- [Tokio](https://tokio.rs/) - Async runtime / 异步运行时
- [rustls](https://github.com/rustls/rustls) - TLS implementation / TLS 实现

---

<a id="chinese-documentation"></a>

## 中文文档 / Chinese Documentation

请参阅上方双语内容。如需纯中文文档，请查看 [USAGE.md](USAGE.md)。

---

## ☕ Support / 支持

If this project is helpful to you, please consider buying me a coffee!

如果这个项目对您有帮助，请考虑请我喝杯咖啡！

<a href="https://buymeacoffee.com/undeadundead" target="_blank">
  <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" height="60">
</a>

**[☕ Buy Me a Coffee / 请我喝咖啡](https://buymeacoffee.com/undeadundead)**

---

**Note / 注意**: This project is for learning and research purposes only. Please comply with local laws and regulations. / 本项目仅供学习和研究使用，请遵守当地法律法规。
