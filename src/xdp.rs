#[cfg(feature = "xdp")]
pub mod loader {
    use aya::programs::{XdpFlags, SchedClassifier, TcAttachType};
    use aya::{include_bytes_aligned, programs::Xdp, Bpf};
    use aya::maps::HashMap;
    use aya_log::EbpfLogger;
    use tracing::{error, info, warn};
    use tokio;

    pub fn start_xdp(iface: &str, ports: Vec<u16>) {
        let iface_name = iface.to_string();
        let protected_ports = ports.clone();

        info!("🛡️  正在初始化内核组件 (XDP + TC Pacing)...");

        // 这里的路径是相对于 User Space crate root 的 (xray-lite/)
        #[cfg(debug_assertions)]
        let program_bytes = include_bytes_aligned!(
            "../xray-lite-ebpf/target/bpfel-unknown-none/release/xray-lite-ebpf"
        );
        #[cfg(not(debug_assertions))]
        let program_bytes = include_bytes_aligned!(
            "../xray-lite-ebpf/target/bpfel-unknown-none/release/xray-lite-ebpf"
        );

        // 1. 加载 BPF (同步进行)
        let mut bpf = match Bpf::load(program_bytes) {
            Ok(b) => b,
            Err(e) => {
                error!("❌ eBPF 固件加载失败 (ELF 解析错误): {}", e);
                return;
            }
        };

        info!("✅ eBPF 固件解析成功！正在尝试挂载到接口: {}", iface_name);

        // 2. 挂载 XDP 程序
        let xdp_prog: &mut Xdp = match bpf.program_mut("xray_firewall") {
            Some(p) => match p.try_into() {
                Ok(p) => p,
                Err(e) => {
                    error!("❌ 无法转换为 XDP 程序类型: {}", e);
                    return;
                }
            },
            None => {
                error!("❌ eBPF 固件中找不到 'xray_firewall' 入口！");
                return;
            }
        };

        if let Err(e) = xdp_prog.load() {
            error!("❌ XDP 程序内核加载失败: {}", e);
            return;
        }

        if let Err(e) = xdp_prog.attach(&iface_name, XdpFlags::default()) {
            warn!("⚠️  XDP Native 挂载失败: {}. 尝试 SKB (Generic) 模式...", e);
            if let Err(e_skb) = xdp_prog.attach(&iface_name, XdpFlags::SKB_MODE) {
                error!("❌ XDP SKB 模式也挂载失败: {}", e_skb);
            } else {
                info!("🚀 XDP 防火墙已通过 SKB 模式挂载成功！");
            }
        } else {
            info!("🚀 XDP 防火墙已通过 Native 模式成功挂载！");
        }

        // 3. 挂载 TC Pacing 程序
        let tc_prog: &mut SchedClassifier = match bpf.program_mut("tc_egress_pacing") {
            Some(p) => match p.try_into() {
                Ok(p) => p,
                Err(e) => {
                    error!("❌ 无法转换为 TC 程序类型: {}", e);
                    return;
                }
            },
            None => {
                error!("❌ eBPF 固件中找不到 'tc_egress_pacing' 入口！");
                return;
            }
        };

        if let Err(e) = tc_prog.load() {
            error!("❌ TC 程序内核加载失败: {}", e);
            return;
        }

        // 显式创建 clsact 队列
        let _ = std::process::Command::new("tc")
            .args(&["qdisc", "add", "dev", &iface_name, "clsact"])
            .output();

        if let Err(e) = tc_prog.attach(&iface_name, TcAttachType::Egress) {
            error!("❌ TC Pacing 挂载失败: {}", e);
        } else {
            info!("🚄 TC Egress Pacing (500Mbps + Jitter) 已成功激活！");
        }

        // 4. 配置端口白名单
        match bpf.map_mut("ALLOWED_PORTS") {
            Some(map) => {
                let ports_map_result: Result<HashMap<_, u16, u8>, _> = HashMap::try_from(map);
                match ports_map_result {
                    Ok(mut ports_map) => {
                        for port in &protected_ports {
                            let _ = ports_map.insert(*port, 1u8, 0);
                            info!("🛡️  端口 {} 已进入 XDP 内核防护白名单", port);
                        }
                    },
                    Err(_) => error!("❌ 无法访问 ALLOWED_PORTS 映射表"),
                }
            },
            None => error!("❌ 找不到 ALLOWED_PORTS 映射表"),
        }

        // 5. 后台启动日志和 GC 循环
        tokio::spawn(async move {
            info!("🔄 启动 eBPF 后台管理任务...");

            // 初始化日志
            if let Err(e) = EbpfLogger::init(&mut bpf) {
                warn!("⚠️  EbpfLogger 初始化失败 (非致命): {}", e);
            }

            loop {
                tokio::time::sleep(std::time::Duration::from_secs(180)).await;
                // ... (GC logic remains the same)

                // --- GC for RATE_LIMIT_MAP ---
                if let Some(map) = bpf.map_mut("RATE_LIMIT_MAP") {
                    // To avoid dependency complexity, we define a local POD struct matching the eBPF one.
                    #[repr(C)]
                    #[derive(Clone, Copy)]
                    struct RateLimitEntry {
                        pub last_time_ns: u64,
                        pub count: u32,
                    }
                    // Safety: Must match eBPF definition exactly.
                    unsafe impl aya::Pod for RateLimitEntry {}

                    // Wrap the map
                    let limit_map_result: Result<HashMap<_, u32, RateLimitEntry>, _> = HashMap::try_from(map);

                    match limit_map_result {
                        Ok(mut limit_map) => {
                            let mut keys_to_remove = Vec::new();
                            
                            // Let's try reading /proc/uptime.
                            if let Ok(uptime_seconds) = std::fs::read_to_string("/proc/uptime") {
                                if let Some(sec_str) = uptime_seconds.split_whitespace().next() {
                                    if let Ok(sec_f64) = sec_str.parse::<f64>() {
                                        let now_ns = (sec_f64 * 1_000_000_000.0) as u64;
                                        let threshold_ns = now_ns.saturating_sub(180 * 1_000_000_000); // 3 mins ago

                                        for item in limit_map.iter() {
                                            if let Ok((k, v)) = item {
                                                if v.last_time_ns < threshold_ns {
                                                    keys_to_remove.push(k);
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            if !keys_to_remove.is_empty() {
                                info!("🧹 GC: Cleaned up {} stale IPs from Rate Limit Map", keys_to_remove.len());
                                for k in keys_to_remove {
                                    let _ = limit_map.remove(&k);
                                }
                            }
                        },
                        Err(e) => warn!("GC: Failed to access RATE_LIMIT_MAP: {}", e),
                    }
                } else {
                    warn!("GC: RATE_LIMIT_MAP not found");
                }

                // --- GC for FLOW_STATE_MAP (TC Pacing) ---
                if let Some(map) = bpf.map_mut("FLOW_STATE_MAP") {
                    #[repr(C)]
                    #[derive(Clone, Copy)]
                    struct FlowState {
                        pub last_tstamp: u64,
                        pub burst_allowance: u64,
                    }
                    unsafe impl aya::Pod for FlowState {}

                    let flow_map_result: Result<HashMap<_, u32, FlowState>, _> = HashMap::try_from(map);
                    match flow_map_result {
                        Ok(mut flow_map) => {
                             let mut keys_to_remove = Vec::new();
                             // Use same logic for time
                             if let Ok(uptime_seconds) = std::fs::read_to_string("/proc/uptime") {
                                if let Some(sec_str) = uptime_seconds.split_whitespace().next() {
                                    if let Ok(sec_f64) = sec_str.parse::<f64>() {
                                        let now_ns = (sec_f64 * 1_000_000_000.0) as u64;
                                        // Flow state expires faster (e.g. 60s)
                                        let threshold_ns = now_ns.saturating_sub(60 * 1_000_000_000); 

                                        for item in flow_map.iter() {
                                            if let Ok((k, v)) = item {
                                                if v.last_tstamp < threshold_ns {
                                                    keys_to_remove.push(k);
                                                }
                                            }
                                        }
                                    }
                                }
                             }

                             if !keys_to_remove.is_empty() {
                                info!("🧹 GC: Cleaned up {} stale Flows from TC Pacing Map", keys_to_remove.len());
                                for k in keys_to_remove {
                                    let _ = flow_map.remove(&k);
                                }
                            }
                        }
                        Err(e) => warn!("GC: Failed to access FLOW_STATE_MAP: {}", e),
                    }
                }
            }
        });
    }
}
