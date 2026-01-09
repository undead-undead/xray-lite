# Fork rustls 实现 Reality 支持 - 实施计划

## 目标

在 rustls 的基础上添加 Reality 协议支持，允许：
1. 修改 ServerHello.random 注入 Reality 认证
2. 验证 ClientHello.SessionID 中的客户端标记
3. 实现回落机制

## 实施步骤

### 阶段 1：准备工作（今天）

- [x] 研究 rustls API 和架构
- [ ] Fork rustls 仓库
- [ ] 在本地项目中使用 path 依赖指向 fork
- [ ] 确保能正常编译

### 阶段 2：最小化修改（1-2 天）

**目标**：在不破坏现有功能的前提下，添加 Reality 支持的最小修改。

#### 2.1 添加 Reality 配置

在 `rustls::ServerConfig` 中添加：
```rust
pub struct RealityConfig {
    pub enabled: bool,
    pub private_key: Vec<u8>,
    pub verify_client: bool,
}
```

#### 2.2 修改 ServerHello 生成

在 `rustls::server::hs::ServerHello` 中：
```rust
// 如果启用 Reality，修改 random 字段
if let Some(reality_config) = config.reality {
    // 注入 HMAC 到 random[20..32]
    inject_reality_auth(&mut random, &reality_config, &client_random);
}
```

#### 2.3 添加 ClientHello 验证

在 `rustls::server::hs::ClientHello` 处理中：
```rust
// 验证 SessionID 中的 Reality 标记
if reality_config.verify_client {
    if !verify_reality_client(&client_hello, &reality_config) {
        // 返回错误或触发回落
        return Err(Error::InvalidReality);
    }
}
```

### 阶段 3：完整实现（3-5 天）

#### 3.1 实现 Reality 认证逻辑

创建 `rustls::reality` 模块：
```rust
pub mod reality {
    pub fn inject_auth(
        server_random: &mut [u8; 32],
        private_key: &[u8],
        client_random: &[u8; 32],
    ) -> Result<()>;
    
    pub fn verify_client(
        session_id: &[u8],
        client_random: &[u8; 32],
        private_key: &[u8],
    ) -> bool;
}
```

#### 3.2 集成到握手流程

修改 `rustls::server::hs::ServerHelloDetails`：
- 在生成 ServerHello 时调用 `inject_auth`
- 在处理 ClientHello 时调用 `verify_client`

#### 3.3 实现回落机制

添加回调接口：
```rust
pub trait RealityFallback {
    fn on_verification_failed(&self, client_hello: &ClientHello) -> FallbackAction;
}

pub enum FallbackAction {
    Reject,
    Forward(SocketAddr), // 转发到 dest
}
```

### 阶段 4：测试和调试（3-5 天）

#### 4.1 单元测试

- [ ] 测试 `inject_auth` 函数
- [ ] 测试 `verify_client` 函数
- [ ] 测试 ServerHello 生成

#### 4.2 集成测试

- [ ] 与 Xray 客户端测试
- [ ] 测试回落机制
- [ ] 测试各种边界情况

#### 4.3 性能测试

- [ ] 对比原版 rustls 的性能
- [ ] 确保 Reality 开销最小

### 阶段 5：文档和发布（1-2 天）

- [ ] 编写 Reality 使用文档
- [ ] 更新 README
- [ ] 创建示例代码
- [ ] 发布到 crates.io（可选）

## 技术细节

### 需要修改的 rustls 文件

1. **src/server/mod.rs**
   - 添加 `RealityConfig` 到 `ServerConfig`

2. **src/server/hs.rs**
   - 修改 `ServerHello` 生成逻辑
   - 添加 `ClientHello` 验证

3. **src/msgs/handshake.rs**
   - 可能需要修改消息结构

4. **新增 src/reality/mod.rs**
   - Reality 认证逻辑
   - HMAC 计算
   - SessionID 验证

### 关键挑战

1. **保持向后兼容**：确保不破坏现有的 rustls 用户
2. **最小化修改**：只修改必要的部分
3. **性能**：Reality 功能不应影响非 Reality 连接的性能
4. **安全性**：确保修改不引入安全漏洞

## 替代方案：使用 rustls 的现有扩展点

在深入修改之前，先尝试使用 rustls 的现有 API：

### 方案 1：自定义 ServerCertResolver

```rust
impl ResolvesServerCert for RealityCertResolver {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        // 验证 Reality 客户端
        if !self.verify_reality_client(&client_hello) {
            return None; // 触发错误，可以在外层处理回落
        }
        Some(self.cert_key.clone())
    }
}
```

**问题**：仍然无法修改 ServerHello.random

### 方案 2：使用 rustls 的 Debug API

rustls 可能有一些未文档化的 debug/internal API，先研究一下。

## 下一步行动

1. **立即**：深入研究 rustls 源码，特别是：
   - `src/server/hs.rs` - 握手逻辑
   - `src/msgs/handshake.rs` - 消息结构
   - `src/server/mod.rs` - 服务器配置

2. **今天完成**：
   - Fork rustls
   - 找到需要修改的确切位置
   - 创建最小化的 PoC

3. **明天**：
   - 实现 Reality 认证逻辑
   - 集成到握手流程
   - 初步测试

## 时间估算

- 阶段 1：0.5 天（今天）
- 阶段 2：2 天
- 阶段 3：4 天
- 阶段 4：4 天
- 阶段 5：1 天

**总计：11-12 天**

## 风险和缓解

### 风险 1：rustls 架构不支持所需修改

**缓解**：如果发现无法在合理范围内修改，立即切换到方案 A（Go FFI）

### 风险 2：修改破坏了 rustls 的安全性

**缓解**：
- 仔细审查每个修改
- 添加大量测试
- 请社区审查

### 风险 3：维护成本过高

**缓解**：
- 保持修改最小化
- 尽量使用 rustls 的扩展点
- 考虑提交 PR 到上游

## 成功标准

1. ✅ 能够与 Xray 客户端成功握手
2. ✅ Reality 认证正确工作
3. ✅ 回落机制正常
4. ✅ 性能损失 < 5%
5. ✅ 所有测试通过
6. ✅ 代码质量达到 rustls 标准
