# rustls Reality 修改方案 - 技术细节

## 关键发现

通过分析 rustls 源码，我找到了需要修改的确切位置：

### 1. ServerHello.random 生成位置

**文件**：`rustls/src/server/tls13.rs`  
**行号**：约 490 行  
**代码**：
```rust
HandshakePayload::ServerHello(ServerHelloPayload {
    legacy_version: ProtocolVersion::TLSv1_2,
    random: Random::from(randoms.server),  // <-- 这里！
    session_id: *session_id,
    cipher_suite: suite.common.suite,
    compression_method: Compression::Null,
    extensions,
}),
```

**修改方案**：
```rust
// 生成 random
let mut server_random = randoms.server;

// 如果启用 Reality，注入认证
if let Some(reality_config) = cx.config.reality_config {
    reality::inject_auth(
        &mut server_random,
        &reality_config.private_key,
        &randoms.client, // ClientHello.random
    )?;
}

HandshakePayload::ServerHello(ServerHelloPayload {
    legacy_version: ProtocolVersion::TLSv1_2,
    random: Random::from(server_random),  // 使用修改后的 random
    session_id: *session_id,
    cipher_suite: suite.common.suite,
    compression_method: Compression::Null,
    extensions,
}),
```

### 2. ClientHello 验证位置

**文件**：`rustls/src/server/tls13.rs`  
**函数**：`handle_client_hello`  
**位置**：在处理 ClientHello 之后，生成 ServerHello 之前

**修改方案**：
```rust
// 在 handle_client_hello 函数中，处理完 ClientHello 后
if let Some(reality_config) = cx.config.reality_config {
    if reality_config.verify_client {
        if !reality::verify_client(
            chm.session_id.as_ref(),
            &chm.random.0,
            &reality_config.private_key,
        ) {
            // 验证失败，触发回落
            if let Some(fallback) = reality_config.fallback {
                return fallback.handle(cx, chm);
            } else {
                return Err(Error::InvalidReality);
            }
        }
    }
}
```

### 3. 配置结构

**文件**：`rustls/src/server/config.rs`  
**修改**：在 `ServerConfig` 中添加 Reality 配置

```rust
pub struct ServerConfig {
    // ... 现有字段 ...
    
    /// Reality protocol configuration
    pub reality_config: Option<Arc<RealityConfig>>,
}

pub struct RealityConfig {
    /// Reality private key (32 bytes)
    pub private_key: Vec<u8>,
    
    /// Whether to verify client authentication
    pub verify_client: bool,
    
    /// Fallback handler for non-Reality clients
    pub fallback: Option<Arc<dyn RealityFallback>>,
}

pub trait RealityFallback: Send + Sync {
    fn handle(
        &self,
        cx: &mut ServerContext,
        client_hello: &ClientHelloPayload,
    ) -> Result<Box<dyn State<ServerConnectionData>>, Error>;
}
```

### 4. Reality 认证模块

**新文件**：`rustls/src/reality/mod.rs`

```rust
use ring::hmac;

/// Inject Reality authentication into ServerHello.random
///
/// Reality protocol injects HMAC-SHA256 authentication into the last 12 bytes
/// of ServerHello.random field.
///
/// Format: random[0..20] = original random
///         random[20..32] = HMAC-SHA256(private_key, server_random[0..20] + client_random)[0..12]
pub fn inject_auth(
    server_random: &mut [u8; 32],
    private_key: &[u8],
    client_random: &[u8; 32],
) -> Result<(), Error> {
    if private_key.len() != 32 {
        return Err(Error::General("Reality private key must be 32 bytes".into()));
    }
    
    // Calculate HMAC
    let key = hmac::Key::new(hmac::HMAC_SHA256, private_key);
    
    let mut message = Vec::with_capacity(20 + 32);
    message.extend_from_slice(&server_random[0..20]);
    message.extend_from_slice(client_random);
    
    let tag = hmac::sign(&key, &message);
    
    // Inject into random[20..32]
    server_random[20..32].copy_from_slice(&tag.as_ref()[0..12]);
    
    Ok(())
}

/// Verify Reality client authentication from ClientHello.session_id
///
/// Reality clients put authentication mark in session_id field.
/// The exact format needs to be determined by analyzing Xray-core implementation.
pub fn verify_client(
    session_id: &[u8],
    client_random: &[u8; 32],
    private_key: &[u8],
) -> bool {
    if session_id.is_empty() {
        return false;
    }
    
    // TODO: Implement correct verification logic
    // Need to study Xray-core's Reality implementation
    
    // Placeholder: check if session_id is not empty
    true
}
```

## 实施步骤

### 步骤 1：Fork rustls（今天）

```bash
# 1. Fork rustls on GitHub
# 2. Clone to local
cd ~/
git clone https://github.com/YOUR_USERNAME/rustls.git rustls-reality
cd rustls-reality

# 3. Create reality branch
git checkout -b reality-support

# 4. Add upstream
git remote add upstream https://github.com/rustls/rustls.git
```

### 步骤 2：创建 Reality 模块（今天）

```bash
# 创建 reality 模块
mkdir rustls/src/reality
touch rustls/src/reality/mod.rs
```

编辑 `rustls/src/lib.rs`，添加：
```rust
pub mod reality;
```

### 步骤 3：修改 ServerConfig（明天）

编辑 `rustls/src/server/config.rs`，添加 Reality 配置字段。

### 步骤 4：修改 TLS 1.3 握手（明天）

编辑 `rustls/src/server/tls13.rs`：
1. 在 ServerHello 生成时注入认证
2. 在 ClientHello 处理时验证客户端

### 步骤 5：测试（后天）

创建测试用例验证：
1. Reality 认证正确注入
2. 客户端验证正常工作
3. 回落机制正常

### 步骤 6：集成到 xray-lite（3-4 天后）

在 `xray-lite/Cargo.toml` 中：
```toml
[dependencies]
rustls = { path = "../rustls-reality/rustls" }
```

## 最小化修改原则

为了保持可维护性，我们遵循以下原则：

1. **不修改核心逻辑**：只在必要的地方添加 Reality 支持
2. **向后兼容**：Reality 功能是可选的，不影响现有用户
3. **清晰的边界**：Reality 相关代码集中在 `reality` 模块
4. **充分测试**：确保修改不破坏现有功能

## 风险评估

### 风险 1：rustls 内部 API 变化

**可能性**：中  
**影响**：高  
**缓解**：
- 锁定 rustls 版本
- 定期同步上游更新
- 保持修改最小化

### 风险 2：性能影响

**可能性**：低  
**影响**：中  
**缓解**：
- Reality 功能仅在启用时生效
- HMAC 计算开销很小
- 进行性能测试

### 风险 3：安全性问题

**可能性**：低  
**影响**：高  
**缓解**：
- 仔细审查代码
- 使用 ring crate 的安全实现
- 请社区审查

## 下一步行动

1. **现在**：Fork rustls 仓库
2. **今天晚些时候**：创建 reality 模块基本结构
3. **明天**：实现核心修改
4. **后天**：测试和调试

准备好开始了吗？
