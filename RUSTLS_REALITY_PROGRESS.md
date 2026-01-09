# rustls Reality 实现进度

## 已完成 ✅

### 阶段 1：准备工作（2026-01-09）

- [x] 深入研究 rustls 源码
- [x] 找到 ServerHello.random 生成位置（`rustls/src/server/tls13.rs:490`）
- [x] 找到 ClientHello 处理位置
- [x] 创建本地 rustls 副本
- [x] 创建 `reality-support` 分支
- [x] 创建 `reality.rs` 模块
- [x] 实现 `inject_auth` 函数
- [x] 实现 `verify_client` 函数（占位符）
- [x] 添加完整的单元测试
- [x] 集成到 rustls lib.rs

**提交**：`21cdf709` - Add Reality protocol support module

## 进行中 🚧

### 阶段 2：配置和集成（预计 2026-01-10）

接下来需要完成：

1. **添加 RealityConfig 到 ServerConfig**
   - 文件：`rustls/src/server/config.rs`
   - 添加 `reality_config: Option<Arc<RealityConfig>>` 字段
   - 定义 `RealityConfig` 结构体
   - 定义 `RealityFallback` trait

2. **修改 TLS 1.3 握手流程**
   - 文件：`rustls/src/server/tls13.rs`
   - 在 ServerHello 生成时调用 `reality::inject_auth`
   - 在 ClientHello 处理时调用 `reality::verify_client`
   - 实现回落逻辑

3. **测试基本功能**
   - 编译 rustls-reality
   - 运行单元测试
   - 创建简单的集成测试

## 待办 📋

### 阶段 3：完整实现（预计 2026-01-11 - 2026-01-13）

- [ ] 完善 `verify_client` 函数（需要研究 Xray-core 实现）
- [ ] 实现回落机制
- [ ] 添加配置验证
- [ ] 添加错误处理
- [ ] 性能优化

### 阶段 4：测试（预计 2026-01-14 - 2026-01-16）

- [ ] 与 Xray 客户端集成测试
- [ ] 测试各种边界情况
- [ ] 性能基准测试
- [ ] 安全审查

### 阶段 5：集成到 xray-lite（预计 2026-01-17 - 2026-01-18）

- [ ] 在 xray-lite 中使用 path 依赖
- [ ] 更新 Reality 服务器实现
- [ ] 端到端测试
- [ ] 文档更新

## 技术细节

### Reality 模块 API

```rust
// 注入认证到 ServerHello.random
pub fn inject_auth(
    server_random: &mut [u8; 32],
    private_key: &[u8],
    client_random: &[u8; 32],
) -> Result<(), Error>

// 验证客户端认证
pub fn verify_client(
    session_id: &[u8],
    client_random: &[u8; 32],
    private_key: &[u8],
) -> bool
```

### 配置结构（计划）

```rust
pub struct RealityConfig {
    pub private_key: Vec<u8>,
    pub verify_client: bool,
    pub fallback: Option<Arc<dyn RealityFallback>>,
}

pub trait RealityFallback: Send + Sync {
    fn handle(&self, cx: &mut ServerContext, client_hello: &ClientHelloPayload) 
        -> Result<Box<dyn State<ServerConnectionData>>, Error>;
}
```

## 下一步行动

### 今天晚些时候

1. 添加 `RealityConfig` 到 `ServerConfig`
2. 修改 TLS 1.3 握手流程
3. 初步测试编译

### 明天

1. 完成握手流程集成
2. 实现基本的回落机制
3. 运行测试

### 后天

1. 研究 Xray-core 的 `verify_client` 实现
2. 完善验证逻辑
3. 集成测试

## 文件结构

```
rustls-reality/
├── rustls/
│   ├── src/
│   │   ├── reality.rs          ✅ 已创建
│   │   ├── lib.rs              ✅ 已修改
│   │   ├── server/
│   │   │   ├── config.rs       🚧 待修改
│   │   │   └── tls13.rs        🚧 待修改
│   │   └── ...
│   └── Cargo.toml
└── ...
```

## 预计时间线

- **今天（2026-01-09）**：完成阶段 1 ✅
- **明天（2026-01-10）**：完成阶段 2
- **2026-01-11 - 2026-01-13**：完成阶段 3
- **2026-01-14 - 2026-01-16**：完成阶段 4
- **2026-01-17 - 2026-01-18**：完成阶段 5

**总计：约 10 天**

## 风险和挑战

### 已解决 ✅

- ✅ 找到 ServerHello.random 生成位置
- ✅ 创建 Reality 模块基本结构
- ✅ 实现 HMAC 认证逻辑

### 待解决 ⚠️

- ⚠️ `verify_client` 的正确实现（需要研究 Xray-core）
- ⚠️ 回落机制的实现细节
- ⚠️ 与 Xray 客户端的兼容性测试

## 参考资料

- rustls 源码：`~/rustls-reality`
- XTLS/REALITY：https://github.com/XTLS/REALITY
- 实施计划：`RUSTLS_REALITY_IMPLEMENTATION_PLAN.md`
- 技术细节：`RUSTLS_REALITY_TECHNICAL_PLAN.md`
