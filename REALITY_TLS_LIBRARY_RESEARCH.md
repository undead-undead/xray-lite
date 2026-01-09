# Reality 基于成熟 TLS 库的实现研究

## 研究目标

使用成熟的 TLS 库（rustls 或 BoringSSL）来实现 Reality 协议，而不是手动实现 TLS 1.3。

## 核心挑战

Reality 协议需要在标准 TLS 1.3 握手的基础上做两个关键修改：

1. **修改 ServerHello.random**：在 random 字段的后 12 字节注入 HMAC 认证
2. **验证 ClientHello.SessionID**：检查客户端是否是合法的 Reality 客户端

## 方案研究

### 方案 1: rustls

**优点**：
- ✅ 纯 Rust，内存安全
- ✅ 已经在项目中使用
- ✅ API 设计良好

**缺点**：
- ❌ **无法修改 ServerHello.random**（这是致命问题）
- ❌ `ServerConnection` 的内部状态是私有的
- ❌ 没有提供握手过程的钩子

**可用的扩展点**：
- `ResolvesServerCert` trait：可以验证 ClientHello，但无法修改 ServerHello
- `ServerConfig`：只能配置静态参数

**结论**：rustls 的 API 设计不允许我们实现 Reality 所需的修改。

### 方案 2: boring (BoringSSL)

**优点**：
- ✅ 更底层的控制
- ✅ BoringSSL 提供了更多的回调
- ✅ Google 和 Cloudflare 使用，稳定可靠

**缺点**：
- ❌ **boring crate 可能不暴露所有需要的 API**
- ❌ 需要学习新的 API
- ❌ 可能需要 unsafe 代码或 FFI

**可用的扩展点**：
- `SSL_CTX_set_tlsext_servername_callback`：SNI 回调
- `SSL_CTX_set_session_id_context`：Session ID 上下文
- 但这些可能还不够修改 ServerHello.random

**结论**：需要进一步研究 boring crate 的源码和 BoringSSL 的 C API。

### 方案 3: openssl

**优点**：
- ✅ rust-openssl crate 成熟
- ✅ OpenSSL 提供了大量的回调和钩子
- ✅ 社区支持好

**缺点**：
- ❌ OpenSSL 的 API 复杂
- ❌ 可能仍然无法直接修改 ServerHello.random
- ❌ 安全性不如 BoringSSL

**结论**：与 boring 类似的问题。

### 方案 4: Fork rustls

**优点**：
- ✅ 完全控制
- ✅ 可以添加 Reality 专用的 API
- ✅ 纯 Rust

**缺点**：
- ❌ **维护成本极高**
- ❌ 需要深入理解 rustls 内部实现
- ❌ 每次 rustls 更新都需要合并

**工作量评估**：
1. Fork rustls 仓库
2. 在 `ServerConnection` 中添加 Reality 模式标志
3. 修改 `ServerHello` 生成逻辑
4. 添加 SessionID 验证钩子
5. 测试和调试
6. 持续维护

**结论**：可行但工作量大，应该作为最后的选择。

### 方案 5: 直接使用 C API (FFI)

**优点**：
- ✅ 完全控制
- ✅ 可以使用 BoringSSL 或 OpenSSL 的所有功能
- ✅ 不依赖 Rust 绑定的完整性

**缺点**：
- ❌ **需要大量 unsafe 代码**
- ❌ 容易出错
- ❌ 失去 Rust 的安全优势

**结论**：不推荐，除非其他方案都不可行。

### 方案 6: 使用 Go 的 REALITY 实现 (CGO)

**优点**：
- ✅ **完全兼容 Xray 客户端**（因为使用相同的代码）
- ✅ 无需重新实现
- ✅ 可以快速验证功能

**缺点**：
- ❌ 需要 Go 运行时
- ❌ FFI 调用开销
- ❌ 失去纯 Rust 的优势
- ❌ 部署复杂度增加

**实现步骤**：
1. 创建 Go 包装器暴露 REALITY 握手函数
2. 使用 cgo 编译为 C 库
3. 在 Rust 中通过 FFI 调用
4. 处理数据传递和错误处理

**结论**：这是最快能工作的方案，但不是最优雅的。

## 关键发现

经过研究，我发现了一个根本性的问题：

**所有主流的 TLS 库（rustls、boring、openssl）都不允许直接修改 ServerHello.random**

这是因为：
1. TLS 库的设计目标是提供标准的、安全的 TLS 实现
2. 修改 ServerHello.random 违反了 TLS 规范（虽然 Reality 有充分的理由这样做）
3. TLS 库不希望用户破坏协议的完整性

## 推荐方案

基于以上研究，我推荐以下路径：

### 短期（1-2 周）：方案 6 - 使用 Go REALITY

**理由**：
- 可以快速验证功能
- 确保与 Xray 客户端完全兼容
- 为长期方案争取时间

**实现**：
1. 创建 Go 包装器
2. 通过 FFI 集成到 Rust
3. 实现基本的 Reality 功能

### 中期（1-2 月）：方案 4 - Fork rustls

**理由**：
- 保持纯 Rust
- 可以贡献回社区
- 长期可维护

**实现**：
1. Fork rustls
2. 添加 `RealityMode` 配置
3. 修改 ServerHello 生成逻辑
4. 提交 PR 或维护自己的 fork

### 长期：贡献到 rustls 社区

如果 Reality 协议被广泛采用，可以考虑：
1. 向 rustls 提议添加"自定义握手钩子"功能
2. 以插件形式实现 Reality
3. 推动 TLS 库支持更多的扩展点

## 下一步行动

1. **立即**：尝试编译 boring crate，检查是否有编译问题
2. **本周**：研究 boring crate 源码，确认是否有未文档化的 API
3. **如果 boring 不可行**：开始实现方案 6（Go FFI）
4. **并行**：研究 rustls fork 的可行性

## 需要回答的问题

1. boring crate 是否提供了修改 ServerHello.random 的方法？
2. 如果需要 fork rustls，工作量有多大？
3. 使用 Go FFI 的性能损失有多大？
4. 是否有其他 Rust TLS 库值得研究？

## 参考资料

- XTLS/REALITY: https://github.com/XTLS/REALITY
- rustls: https://github.com/rustls/rustls
- boring: https://github.com/cloudflare/boring
- rust-openssl: https://github.com/sfackler/rust-openssl
