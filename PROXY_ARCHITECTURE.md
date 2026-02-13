# Xray-Lite v0.6.0-xdp 核心工作流程与架构说明

本文档详细描述了 `v0.6.0-xdp` 版本的网络流量处理全过程，涵盖 **协议层 (Reality/XHTTP)**、**内核防火墙 (XDP)** 以及 **eBPF 状态机** 的交互机制。

---

## 1. 总体架构概览

该版本核心设计理念为 **"应用层火力全开，内核层极简防御"**。通过剥离可能引起调度冲突的 TC Pacing，让 Linux 原生网络栈负责流控，同时利用 XDP 在网卡驱动层高效过滤垃圾流量。

### 核心组件
1.  **XDP Firewall (内核态)**: 运行在网卡驱动层，微秒级处理入站流量。
2.  **Kernel TCP Stack (内核态)**: 使用标准的 BBR/CUBIC 拥塞控制和 FQ 调度。
3.  **Application Layer (用户态)**:
    *   **XTLS-Reality**: 基于 TLS 1.3 的伪装与反向代理。
    *   **XHTTP (HTTP/2)**: 高性能多路复用传输。

---

## 2. 详细流量处理流程

### 阶段一：入站流量 (Ingress) - XDP 防御前线

当一个数据包到达网卡 (`eth0`) 时，首先触发挂载在 XDP 钩子上的 `xray_firewall` 程序：

#### A. 协议类型检查
1.  **非 IPv4**: 直接放行 (`PASS`)。
2.  **UDP 包 (QUIC/H3/DNS)**:
    *   检查 **目的端口** 是否在 `ALLOWED_PORTS` 白名单中（如 443）。
    *   **在白名单**: **放行 (`PASS`)**。*(注：这是 v0.6.0 修正的关键逻辑，此前为错误丢弃)*
    *   **不在白名单**: **丢弃 (`DROP`)**。防止 UDP 反射攻击或非业务端口扫描。
3.  **TCP 包**:
    *   检查 **目的端口** 是否在白名单。
    *   **不在白名单**: **放行 (`PASS`)**。（允许 SSH 等管理流量通过，因为它们不经过 VLESS 端口）。
    *   **在白名单 (443)**: 进入深度检查。

#### B. TCP SYN 泛洪防御 (针对白名单端口)
1.  **Flag 检查**: 仅针对 `SYN` 包（新建连接请求）。
2.  **速率限制 (Rate Limit)**:
    *   使用 eBPF Map (`RATE_LIMIT_MAP`) 记录该源 IP (`src_ip`) 的 `SYN` 包到达时间和计数。
    *   如果该 IP 在 **1秒内** 发送超过 **1000个** SYN 包（阈值已放宽）：
    *   **动作**: 直接 **丢弃 (`DROP`)** 并记录日志。
    *   **效果**: 保护后端服务不被 SYN Flood 打瘫，同时 1000/s 的阈值确保正常的高并发浏览器访问不会被误杀。

---

### 阶段二：内核协议栈与握手 (Kernel Stack)

通过 XDP 的包进入 Linux 内核协议栈。内核完成 TCP 三次握手或 UDP 会话建立。

*   **TCP 拥塞控制**: 默认使用系统配置的算法（推荐 BBR）。
*   **TCP 调度**: 使用 `sch_fq` (Fair Queueing) 进行公平调度，不再受自定义 eBPF Pacing 干扰。

---

### 阶段三：应用层处理 (Userspace)

数据被 `tokio` 异步运行时读取，根据配置分发给 Reality 或 XHTTP 处理器。

#### A. XTLS-Reality (TCP/UDP)
这是目前最强的抗探测协议，伪装成正常的 TLS 流量。
1.  **Steal the Handshake**: 服务端接收 Client Hello，利用 eBPF 或应用层逻辑从目标网站（Fallback Dest）"借用" 证书链。
2.  **SNI 验证**: 检查 SNI 是否符合配置的目标域名。
3.  **指纹模拟**: 模拟真实浏览器（如 Chrome）的 TLS 指纹。
4.  **数据传输**:
    *   握手成功后，建立加密隧道。
    *   之后的数据传输完全看起来像正常的 HTTPS 流量。

#### B. XHTTP (基于 HTTP/2)
这是针对高并发和复杂网络环境优化的传输层。
1.  **H2 握手**: 建立标准的 HTTP/2 连接。
2.  **动态窗口升级 (Dynamic Window Upgrade)**:
    *   **初始状态**: 模拟 Nginx/Apache 默认行为，初始窗口设为 **64KB**。这为了骗过某些针对"大窗口起步"的 DPI 检测。
    *   **身份验证后**: 一旦 Reality/VLESS 验证通过，服务端立即发送 `WINDOW_UPDATE` 帧。
    *   **升级动作**: 将连接级流控窗口从 64KB 瞬间扩容至 **5MB**。
    *   **目的**: 允许在长肥管道（大带宽、高延迟，如跨海线路）上跑满带宽 (500Mbps+)。
3.  **伪装头拆分**:
    *   服务端返回 `Server: nginx/1.26.0` 等伪装 Header。
    *   数据发送时使用类似 `nginx` 的分片策略，避免特征数据包长度。

---

### 阶段四：出站流量 (Egress) - 纯净转发

在 v0.6.0-xdp 最终版中，**出站方向没有任何 eBPF 干扰**。

1.  **应用层发送**: `vless-server` 调用 `write()` 发送 5MB 窗口内的数据。
2.  **内核排队**: 数据包进入 `eth0` 的 `qdisc` 队列（通常是 `fq`）。
3.  **物理发送**: 网卡驱动直接发包。
4.  **无 TC 挂载**: `tc filter show dev eth0 egress` 为空。这意味着：
    *   没有额外的 CPU 开销。
    *   没有时间戳计算冲突。
    *   BBR 算法全权负责探测带宽和控制发送速率。

---

## 3. 性能与安全总结

| 组件 | 状态 | 作用 | 关键参数 |
| :--- | :--- | :--- | :--- |
| **XDP Firewall** | ✅ **Active** | 丢弃非白名单 UDP (防反射)，清洗 TCP SYN 洪水 | UDP: PASS Allowed / DROP Others<br>TCP SYN: Max 1000/s per IP |
| **TC Pacing** | ❌ **Removed** | (已移除) 曾用于平滑流量，但导致兼容性断流 | N/A (完全依赖 Kernel FQ) |
| **Reality** | ✅ **Active** | TLS 1.3 完美伪装 | 目标 SNI 劫持 |
| **XHTTP** | ✅ **Active** | H2 多路复用 + 动态窗口 | **Init Window: 64KB -> 5MB** |

### 诊断自查
*   **连不上?** 检查 XDP 是否错误拦截（日志里有没有 Dropped）。v0.6.0 已修复允许 UDP 白名单。
*   **速度慢?** 检查 BBR 是否开启 (`sysctl net.ipv4.tcp_congestion_control`)。我们现在的应用层已支持 5MB 大窗口，只要内核不限速，就能跑满。
