# Xray-Lite

A lightweight, high-performance VLESS + Reality proxy server implemented in pure Rust. Fully compatible with all Xray/V2Ray clients.

一个轻量级、高性能的纯 Rust 实现的 VLESS + Reality 代理服务器。完全兼容所有 Xray/V2Ray 客户端。

[Documentation](https://github.com/undead-undead/xray-lite/wiki) | [Report Bug](https://github.com/undead-undead/xray-lite/issues)

## Key Features / 核心特性

*   🚀 **Extreme Performance**: Built with Rust, native `epoll` / `io_uring` support for low latency and high concurrency.
*   🔒 **Secure by Design**: Memory-safe implementation, minimal attack surface.
*   🛡️ **XDP Firewall** (New!): Kernel-level defense against `UDP Flood`, `TCP SYN Flood`, and `Illegal Packets`.
*   🎭 **Stealthy**: Reality protocol support for perfect camouflage.
*   📦 **Static Binary**: Zero dependencies, runs on any Linux distro.

## Quick Installation / 快速安装

> **Note**: This is a **static compilation version** that works perfectly on **any Linux system** (Debian, Ubuntu, CentOS, Alpine, etc.) without dependency issues.
>
> **注意**：此为**静态编译版本**，完美适配**任何 Linux 系统** (Debian, Ubuntu, CentOS, Alpine 等)，无需担心依赖问题。

### 1. Standard Installation (Recommended) / 标准版安装（推荐）

> **Current Version: v0.5.2 (Stable)**

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/undead-undead/xray-lite/main/install.sh)
```

### 2. XDP Installation (Performance Enhanced) / XDP 版安装（性能增强版）

> **Current Version: v0.6.0-xdp (Rate Limit)**
> 
> **Requirements**: Linux Kernel ≥ 5.4 (AMD64 only), Root privileges.

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/undead-undead/xray-lite/feature/dynamic-xdp/install.sh)
```

**New XDP/TC Features / XDP/TC 新特性:**
*   🛡️ **XDP Firewall**: Kernel-level protection against **UDP Floods**, **TCP SYN Floods**, and **Illegal Flags**. / 内核级 UDP 洪水、TCP SYN 洪水及非法标志位防御。
*   � **TC-BPF EDT Pacing**: Sophisticated **EDT (Earliest Departure Time)** based traffic shaping with **Micro-Jitter** and **Bursting**. / 基于 EDT 的内核级流量整形，支持微秒级抖动与自适应突发，消除流量指纹。
*   👻 **Ultimate Stealth**: Silent packet dropping (DROP) in kernel space, making the server indistinguishable from a standard Web server. / 在内核层静默丢弃探测包，使其与标准 Web 服务器无异。
*   🎭 **Smart Protection**: Only protects configured VLESS ports, ensuring other services (like SSH) remain untouched. / 仅保护配置端口，不影响 SSH 等其他正常服务。

The script will: / 脚本将自动：
1. Detect Kernel & Architecture / 检测内核与架构
2. Download optimized XDP binary / 下载 XDP 优化版二进制
3. Auto-attach XDP program to NIC / 自动挂载 XDP 程序到网卡
4. Generate keys and start service / 生成密钥并启动服务

### 3. Build from Source / 从源码构建

```bash
# Clone the repository / 克隆仓库
git clone https://github.com/undead-undead/xray-lite.git
cd xray-lite

# Build Release version / 编译发布版
cargo build --release

# Run / 运行
./target/release/vless-server -c config.json
```

## Configuration / 配置

### config.json

```json
{
  "log": {
    "level": "info",
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log"
  },
  "inbounds": [
    {
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "your-uuid-here",
            "flow": ""
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "www.microsoft.com:443",
          "xver": 0,
          "serverNames": [
            "www.microsoft.com",
            "www.bing.com"
          ],
          "privateKey": "your-private-key",
          "shortIds": [
            ""
          ]
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom"
    }
  ]
}
```

## Contributing / 贡献

We welcome all kinds of contributions! Please verify that `cargo test` passes before submitting a PR.
欢迎各种形式的贡献！提交 PR 前请确保通过 `cargo test`。

## License / 许可证

[MPL-2.0](LICENSE)
