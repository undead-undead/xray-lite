# VLESS+Reality+XHTTP Rust 实现方案

## 项目概述

本项目旨在使用 Rust 重写 Xray 的 VLESS+Reality+XHTTP 核心功能，打造一个轻量级、高性能的代理工具。

## 技术架构

### 核心技术栈
- **异步运行时**: Tokio (高性能异步 I/O)
- **TLS 库**: rustls + tokio-rustls (安全的 TLS 1.3 实现)
- **HTTP/2**: h2 crate (HTTP/2 协议支持)
- **加密**: ring, x25519-dalek (密码学原语)
- **序列化**: serde, serde_json (配置文件处理)

### 协议层次结构

```
┌─────────────────────────────────────┐
│      应用层 (Application)            │
│   - 配置管理                         │
│   - 路由控制                         │
└─────────────────────────────────────┘
           ↓
┌─────────────────────────────────────┐
│      协议层 (Protocol)               │
│   - VLESS 协议实现                   │
│   - UUID 认证                        │
└─────────────────────────────────────┘
           ↓
┌─────────────────────────────────────┐
│      传输层 (Transport)              │
│   - XHTTP (HTTP/1.1, HTTP/2)        │
│   - Reality (TLS 伪装)              │
└─────────────────────────────────────┘
           ↓
┌─────────────────────────────────────┐
│      网络层 (Network)                │
│   - TCP/UDP Socket                  │
│   - 双向数据转发                     │
└─────────────────────────────────────┘
```

## 模块化设计

### 1. 核心模块 (Core)

#### 1.1 配置模块 (`config`)
```rust
// src/config/mod.rs
pub struct Config {
    pub inbounds: Vec<Inbound>,
    pub outbounds: Vec<Outbound>,
    pub routing: RoutingConfig,
}

pub struct Inbound {
    pub protocol: Protocol,
    pub listen: String,
    pub port: u16,
    pub settings: InboundSettings,
    pub stream_settings: StreamSettings,
}

pub struct StreamSettings {
    pub network: Network,      // tcp, http
    pub security: Security,     // reality, tls, none
    pub reality_settings: Option<RealitySettings>,
    pub xhttp_settings: Option<XhttpSettings>,
}
```

**职责**:
- 配置文件解析 (JSON/YAML)
- 配置验证
- 默认值处理

#### 1.2 协议模块 (`protocol`)

##### VLESS 子模块 (`protocol::vless`)
```rust
// src/protocol/vless/mod.rs
pub struct VlessCodec {
    uuid: Uuid,
}

pub struct VlessRequest {
    pub version: u8,
    pub uuid: Uuid,
    pub command: Command,
    pub address: Address,
    pub port: u16,
}

pub struct VlessResponse {
    pub version: u8,
    pub addon_length: u8,
}
```

**职责**:
- VLESS 协议编解码
- UUID 认证
- 请求/响应处理
- 地址解析 (IPv4/IPv6/域名)

**关键实现**:
```rust
impl VlessCodec {
    pub async fn decode_request(&mut self, buf: &[u8]) -> Result<VlessRequest>;
    pub async fn encode_response(&mut self, resp: VlessResponse) -> Result<Vec<u8>>;
    pub fn validate_uuid(&self, uuid: &Uuid) -> bool;
}
```

### 2. 传输模块 (Transport)

#### 2.1 Reality 模块 (`transport::reality`)
```rust
// src/transport/reality/mod.rs
pub struct RealityConfig {
    pub dest: String,           // 目标网站
    pub server_names: Vec<String>,
    pub private_key: [u8; 32],
    pub public_key: [u8; 32],
    pub short_ids: Vec<Vec<u8>>,
    pub fingerprint: String,    // chrome, firefox, safari
}

pub struct RealityServer {
    config: RealityConfig,
    tls_acceptor: TlsAcceptor,
}
```

**职责**:
- TLS 1.3 握手伪装
- 客户端指纹模拟 (uTLS)
- ServerHello 修改
- 流量转发到真实网站

**关键技术点**:
1. **X25519 密钥交换**: 用于 Reality 认证
2. **TLS 指纹伪装**: 模拟真实浏览器
3. **SNI 处理**: 伪装成访问合法网站
4. **证书劫持**: 使用目标网站的证书链

**实现流程**:
```rust
impl RealityServer {
    pub async fn accept(&self, stream: TcpStream) -> Result<RealityStream> {
        // 1. 接收 ClientHello
        let client_hello = self.read_client_hello(&stream).await?;
        
        // 2. 验证 SNI 和 short_id
        self.validate_client(&client_hello)?;
        
        // 3. 转发到真实网站获取 ServerHello
        let server_hello = self.fetch_real_server_hello(&client_hello).await?;
        
        // 4. 修改 ServerHello (注入 Reality 标识)
        let modified_hello = self.modify_server_hello(server_hello)?;
        
        // 5. 返回修改后的握手
        stream.write_all(&modified_hello).await?;
        
        Ok(RealityStream::new(stream))
    }
}
```

#### 2.2 XHTTP 模块 (`transport::xhttp`)
```rust
// src/transport/xhttp/mod.rs
pub struct XhttpConfig {
    pub mode: XhttpMode,        // packet-up, stream-up
    pub path: String,
    pub host: String,
}

pub enum XhttpMode {
    PacketUp,   // 数据包模式
    StreamUp,   // 流模式 (适合 CDN)
}

pub struct XhttpServer {
    config: XhttpConfig,
}
```

**职责**:
- HTTP/1.1 和 HTTP/2 支持
- 上下行流量分离
- CDN 穿透优化
- WebSocket 升级 (可选)

**实现策略**:
```rust
impl XhttpServer {
    pub async fn handle_request(&self, req: Request<Body>) -> Result<Response<Body>> {
        match self.config.mode {
            XhttpMode::PacketUp => self.handle_packet_mode(req).await,
            XhttpMode::StreamUp => self.handle_stream_mode(req).await,
        }
    }
    
    // 流模式: 模拟 gRPC 流量
    async fn handle_stream_mode(&self, req: Request<Body>) -> Result<Response<Body>> {
        // 设置 gRPC 头部
        let mut resp = Response::new(Body::empty());
        resp.headers_mut().insert("content-type", "application/grpc");
        resp.headers_mut().insert("grpc-encoding", "identity");
        
        // 建立双向流
        Ok(resp)
    }
}
```

### 3. 网络模块 (Network)

#### 3.1 连接管理 (`network::connection`)
```rust
// src/network/connection.rs
pub struct ConnectionManager {
    inbound_listener: TcpListener,
    outbound_pool: ConnectionPool,
}

pub struct ProxyConnection {
    client_stream: Box<dyn AsyncReadWrite>,
    remote_stream: Box<dyn AsyncReadWrite>,
}
```

**职责**:
- TCP 连接监听
- 连接池管理
- 双向数据转发
- 连接超时处理

**核心转发逻辑**:
```rust
impl ProxyConnection {
    pub async fn relay(&mut self) -> Result<()> {
        let (mut client_read, mut client_write) = tokio::io::split(&mut self.client_stream);
        let (mut remote_read, mut remote_write) = tokio::io::split(&mut self.remote_stream);
        
        let client_to_remote = tokio::io::copy(&mut client_read, &mut remote_write);
        let remote_to_client = tokio::io::copy(&mut remote_read, &mut client_write);
        
        // 并发执行双向转发
        tokio::try_join!(client_to_remote, remote_to_client)?;
        
        Ok(())
    }
}
```

#### 3.2 路由模块 (`network::routing`)
```rust
// src/network/routing.rs
pub struct Router {
    rules: Vec<RoutingRule>,
}

pub enum RoutingRule {
    Domain(DomainMatcher),
    IP(IpMatcher),
    GeoIP(GeoIPMatcher),
}
```

**职责**:
- 域名/IP 路由
- GeoIP 分流
- 规则匹配

### 4. 工具模块 (Utils)

#### 4.1 加密工具 (`utils::crypto`)
```rust
// src/utils/crypto.rs
pub fn generate_x25519_keypair() -> (PublicKey, PrivateKey);
pub fn compute_shared_secret(private: &PrivateKey, public: &PublicKey) -> SharedSecret;
```

#### 4.2 UUID 工具 (`utils::uuid`)
```rust
// src/utils/uuid.rs
pub fn parse_uuid(s: &str) -> Result<Uuid>;
pub fn generate_uuid() -> Uuid;
```

## 项目结构

```
vless-reality-xhttp-rust/
├── Cargo.toml
├── src/
│   ├── main.rs                 # 程序入口
│   ├── lib.rs                  # 库入口
│   │
│   ├── config/                 # 配置模块
│   │   ├── mod.rs
│   │   ├── parser.rs           # 配置解析
│   │   └── validator.rs        # 配置验证
│   │
│   ├── protocol/               # 协议模块
│   │   ├── mod.rs
│   │   └── vless/
│   │       ├── mod.rs
│   │       ├── codec.rs        # 编解码器
│   │       ├── request.rs      # 请求处理
│   │       ├── response.rs     # 响应处理
│   │       └── address.rs      # 地址解析
│   │
│   ├── transport/              # 传输模块
│   │   ├── mod.rs
│   │   ├── reality/
│   │   │   ├── mod.rs
│   │   │   ├── server.rs       # Reality 服务端
│   │   │   ├── client.rs       # Reality 客户端
│   │   │   ├── tls.rs          # TLS 处理
│   │   │   └── fingerprint.rs  # 指纹伪装
│   │   │
│   │   └── xhttp/
│   │       ├── mod.rs
│   │       ├── server.rs       # XHTTP 服务端
│   │       ├── client.rs       # XHTTP 客户端
│   │       ├── h1.rs           # HTTP/1.1 实现
│   │       └── h2.rs           # HTTP/2 实现
│   │
│   ├── network/                # 网络模块
│   │   ├── mod.rs
│   │   ├── connection.rs       # 连接管理
│   │   ├── listener.rs         # 监听器
│   │   ├── routing.rs          # 路由
│   │   └── pool.rs             # 连接池
│   │
│   ├── utils/                  # 工具模块
│   │   ├── mod.rs
│   │   ├── crypto.rs           # 加密工具
│   │   ├── uuid.rs             # UUID 工具
│   │   └── error.rs            # 错误处理
│   │
│   └── server.rs               # 服务器主逻辑
│
├── tests/                      # 集成测试
│   ├── vless_test.rs
│   ├── reality_test.rs
│   └── xhttp_test.rs
│
├── benches/                    # 性能测试
│   └── throughput.rs
│
├── examples/                   # 示例代码
│   ├── server.rs
│   └── client.rs
│
└── config.json                 # 示例配置
```

## 依赖清单 (Cargo.toml)

```toml
[package]
name = "vless-reality-xhttp"
version = "0.1.0"
edition = "2021"

[dependencies]
# 异步运行时
tokio = { version = "1.35", features = ["full"] }
tokio-util = { version = "0.7", features = ["codec"] }

# TLS
rustls = "0.22"
tokio-rustls = "0.25"
rustls-pemfile = "2.0"

# HTTP/2
h2 = "0.4"
hyper = { version = "1.0", features = ["full"] }
hyper-util = "0.1"

# 加密
ring = "0.17"
x25519-dalek = "2.0"
sha2 = "0.10"
aes-gcm = "0.10"

# UUID
uuid = { version = "1.6", features = ["v4", "serde"] }

# 序列化
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
toml = "0.8"

# 日志
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }

# 错误处理
anyhow = "1.0"
thiserror = "1.0"

# 网络工具
bytes = "1.5"
futures = "0.3"

# 其他
clap = { version = "4.4", features = ["derive"] }
rand = "0.8"

[dev-dependencies]
criterion = "0.5"
```

## 实现路线图

### Phase 1: 基础框架 (Week 1-2)
- [x] 项目初始化
- [ ] 配置模块实现
- [ ] 基础网络层 (TCP 监听和转发)
- [ ] 日志系统集成
- [ ] 错误处理框架

### Phase 2: VLESS 协议 (Week 3-4)
- [ ] VLESS 请求解码
- [ ] VLESS 响应编码
- [ ] UUID 认证机制
- [ ] 地址解析 (IPv4/IPv6/域名)
- [ ] 单元测试

### Phase 3: Reality 传输 (Week 5-7)
- [ ] X25519 密钥生成
- [ ] TLS 1.3 握手处理
- [ ] ClientHello 解析
- [ ] ServerHello 修改
- [ ] 指纹伪装 (Chrome/Firefox/Safari)
- [ ] 与真实网站交互
- [ ] 集成测试

### Phase 4: XHTTP 传输 (Week 8-9)
- [ ] HTTP/1.1 实现
- [ ] HTTP/2 实现
- [ ] packet-up 模式
- [ ] stream-up 模式
- [ ] gRPC 头部伪装
- [ ] 性能测试

### Phase 5: 集成与优化 (Week 10-11)
- [ ] 完整流程集成
- [ ] 路由功能
- [ ] 连接池优化
- [ ] 内存优化
- [ ] 性能基准测试

### Phase 6: 测试与文档 (Week 12)
- [ ] 端到端测试
- [ ] 与 Xray 兼容性测试
- [ ] 文档编写
- [ ] 示例代码
- [ ] 发布准备

## 关键技术挑战

### 1. Reality TLS 伪装
**挑战**: 需要精确模拟真实浏览器的 TLS 指纹
**解决方案**:
- 使用 rustls 的底层 API
- 实现自定义 ClientHello 生成
- 参考 uTLS 的指纹库

### 2. XHTTP CDN 穿透
**挑战**: 需要模拟 gRPC 流量特征
**解决方案**:
- 正确设置 HTTP/2 头部
- 实现流式传输
- 支持多路复用

### 3. 高性能数据转发
**挑战**: 最小化延迟和内存拷贝
**解决方案**:
- 使用 `tokio::io::copy_bidirectional`
- 零拷贝优化
- 连接池复用

### 4. 协议兼容性
**挑战**: 与 Xray 客户端/服务端完全兼容
**解决方案**:
- 严格遵循 VLESS 协议规范
- 对照 Xray 源码实现
- 交叉测试

## 性能目标

- **吞吐量**: ≥ 1 Gbps (单核)
- **延迟**: < 5ms (本地转发)
- **内存占用**: < 50MB (空闲)
- **并发连接**: ≥ 10,000

## 安全考虑

1. **密钥管理**: 安全存储私钥，支持密钥轮换
2. **时间攻击**: 使用常量时间比较
3. **内存安全**: 利用 Rust 的所有权系统
4. **依赖审计**: 定期更新依赖，使用 `cargo audit`

## 配置示例

```json
{
  "inbounds": [
    {
      "protocol": "vless",
      "listen": "0.0.0.0",
      "port": 443,
      "settings": {
        "clients": [
          {
            "id": "b831381d-6324-4d53-ad4f-8cda48b30811",
            "flow": ""
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "dest": "www.apple.com:443",
          "serverNames": ["www.apple.com"],
          "privateKey": "your_private_key",
          "shortIds": ["0123456789abcdef"]
        },
        "xhttpSettings": {
          "mode": "stream-up",
          "path": "/",
          "host": "www.apple.com"
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct"
    }
  ]
}
```

## 测试策略

### 单元测试
- 每个模块独立测试
- 覆盖率 > 80%

### 集成测试
- VLESS + Reality 组合测试
- VLESS + XHTTP 组合测试
- 完整链路测试

### 性能测试
- 使用 Criterion 进行基准测试
- 压力测试 (1000+ 并发连接)
- 内存泄漏检测

### 兼容性测试
- 与 Xray-core 客户端对接
- 与 v2rayN/v2rayNG 客户端测试
- 多平台测试 (Linux/macOS/Windows)

## 部署建议

### 编译优化
```toml
[profile.release]
opt-level = 3
lto = true
codegen-units = 1
strip = true
```

### 运行参数
```bash
# 生产环境
./vless-reality-xhttp --config config.json --log-level info

# 开发环境
RUST_LOG=debug ./vless-reality-xhttp --config config.json
```

## 参考资源

1. **Xray-core 源码**: https://github.com/XTLS/Xray-core
2. **VLESS 协议规范**: https://xtls.github.io/development/protocols/vless.html
3. **Reality 文档**: https://github.com/XTLS/REALITY
4. **Tokio 文档**: https://tokio.rs/
5. **rustls 文档**: https://docs.rs/rustls/

## 贡献指南

欢迎贡献代码！请遵循以下规范:
- 使用 `cargo fmt` 格式化代码
- 使用 `cargo clippy` 检查代码质量
- 编写单元测试
- 更新文档

## 许可证

MIT License
