#[cfg(feature = "xdp")]
pub mod loader {
    use aya::programs::{XdpFlags, SchedClassifier, TcAttachType};
    use aya::{include_bytes_aligned, programs::Xdp, Bpf};
    use aya::maps::HashMap;
    use aya_log::EbpfLogger;
    use tracing::{error, info, warn};
    use tokio;

    pub fn start_xdp(iface: &str, ports: Vec<u16>) {
        let iface = iface.to_string();
        let ports = ports.clone();

        // Must use tokio::spawn to provide Reactor context for aya::log
        tokio::spawn(async move {
            info!("正在初始化 XDP 防火墙，接口: {}", iface);

            // 加载逻辑
            // 这里的路径是相对于 User Space crate root 的 (xray-lite/)
            #[cfg(debug_assertions)]
             let program_bytes = include_bytes_aligned!(
                "../xray-lite-ebpf/target/bpfel-unknown-none/release/xray-lite-ebpf"
            );
            #[cfg(not(debug_assertions))]
            let program_bytes = include_bytes_aligned!(
                "../xray-lite-ebpf/target/bpfel-unknown-none/release/xray-lite-ebpf"
            );

            // 加载 BPF
            let mut bpf = match Bpf::load(program_bytes) {
                Ok(b) => b,
                Err(e) => {
                    error!("XDP 加载失败: {}", e);
                    return;
                }
            };

            // 初始化日志：必须在 Tokio Runtime 上下文中调用
            if let Err(e) = EbpfLogger::init(&mut bpf) {
                warn!("XDP EbpfLogger 初始化失败 (非致命): {}", e);
            }

            // 挂载 XDP 程序
            let program: &mut Xdp = match bpf.program_mut("xray_firewall") {
                Some(p) => match p.try_into() {
                    Ok(p) => p,
                    Err(e) => {
                        error!("无法转换为 XDP 程序: {}", e);
                        return;
                    }
                },
                None => {
                    error!("eBPF 固件中找不到 'xray_firewall' 程序！");
                    return;
                }
            };

            if let Err(e) = program.load() {
                error!("XDP 程序加载到内核失败: {}", e);
                return;
            }

            // Try attach in default (Driver) mode first
            if let Err(e) = program.attach(&iface, XdpFlags::default()) {
                warn!("XDP Native (Driver) attach failed: {}. Falling back to SKB (Generic) mode...", e);
                // Fallback to SKB (Generic) mode
                // Note: SKB mode is slower but works on almost all drivers/kernels
                if let Err(e_skb) = program.attach(&iface, XdpFlags::SKB_MODE) {
                    error!("XDP SKB (Generic) attach also failed: {}", e_skb);
                    return;
                }
                info!("⚠️ Falling back to XDP SKB (Generic) mode. Performance might be reduced but still better than iptables.");
            }

            info!(
                "🚀 XDP 防火墙已成功挂载到 {}！高性能内核级过滤生效中。",
                iface
            );

            // --- Attach TC Egress Pacing ---
            info!("正在挂载 TC Egress Pacing 程序...");
            let tc_prog: &mut SchedClassifier = match bpf.program_mut("tc_egress_pacing") {
                Some(p) => match p.try_into() {
                    Ok(p) => p,
                    Err(e) => {
                        error!("无法转换为 TC 程序: {}", e);
                        return;
                    }
                },
                None => {
                    error!("eBPF 固件中找不到 'tc_egress_pacing' 程序！");
                    return;
                }
            };

            if let Err(e) = tc_prog.load() {
                error!("TC 程序加载到内核失败: {}", e);
                return;
            }

            // 强制清理并确保 clsact 存在 (使用系统 shell 命令确保最高兼容性)
            let _ = std::process::Command::new("tc")
                .args(&["qdisc", "add", "dev", &iface, "clsact"])
                .output();

            match tc_prog.attach(&iface, TcAttachType::Egress) {
                Ok(_) => info!("🚄 TC Egress Pacing (EDT + Jitter) 已成功挂载到 {} 接口！", iface),
                Err(e) => error!("TC Egress Pacing 挂载失败: {}", e),
            }

            // --- Configure Dynamic Ports ---
            match bpf.map_mut("ALLOWED_PORTS") {
                Some(map) => {
                    // Enforce type <_, u16, u8> to match eBPF definition
                    let ports_map_result: Result<HashMap<_, u16, u8>, _> = HashMap::try_from(map);
                    match ports_map_result {
                        Ok(mut ports_map) => {
                            for port in &ports {
                                if let Err(e) = ports_map.insert(*port, 1u8, 0) {
                                    error!("Failed to add port {} to XDP Map: {}", port, e);
                                } else {
                                    info!("🛡️  Port {} is now protected by XDP Kernel Firewall (DROP non-TLS)", port);
                                }
                            }
                        },
                        Err(e) => error!("Failed to access ALLOWED_PORTS map as HashMap: {}", e),
                    }
                },
                None => error!("XDP Map 'ALLOWED_PORTS' not found in eBPF program!"),
            }

            // --- Garbage Collection Loop ---
            loop {
                // Sleep for 3 minutes
                tokio::time::sleep(std::time::Duration::from_secs(180)).await;

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
