#[cfg(feature = "xdp")]
pub mod loader {
    use aya::programs::XdpFlags;
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
            let program: &mut Xdp = match bpf.program_mut("xdp_firewall").unwrap().try_into() {
                Ok(p) => p,
                Err(e) => {
                    error!("无法获取 xdp_firewall 程序: {}", e);
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

                // Perform GC
                if let Some(map) = bpf.map_mut("RATE_LIMIT_MAP") {
                    // Try to borrow as HashMap. 
                    // Note: In aya, maps are not async, so this might block slightly, but it's user space.
                    // u32 key (src_ip), RateLimitEntry value (need to define struct layout or read raw bytes)
                    // Simplified: We assume we can access it using the PerCpuHashMap or HashMap wrapper.
                    // However, we need the exact struct definition from ebpf crate to decode "RateLimitEntry".
                    // Since we can't easily import "RateLimitEntry" from the ebpf crate here without a dependency cycle 
                    // or code duplication, and given this is a quick fix, let's use the raw primitive approach if possible, 
                    // OR (better) just clean by time if we can decode the struct similarly to how eBPF does.

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
                            // Kernel uses CLOCK_MONOTONIC (bpf_ktime_get_ns).
                            // We need a comparable timestamp. Rust's Instant::now() often maps to CLOCK_MONOTONIC.
                            // But to be precise, we should diff against the "last_time_ns" recorded.
                            // Actually, bpf_ktime_get_ns() is usually boot time. 
                            // std::time::Instant uses an opaque value, but we can check elapsed time.
                            //
                            // WAIT: The eBPF store `last_time_ns` from `bpf_ktime_get_ns()`.
                            // User space cannot easily get the EXACT same clock reference without `libc::clock_gettime(CLOCK_MONOTONIC, ...)`.
                            //
                            // Let's use a heuristic: Any entry not updated deeply in the past is stale.
                            // BUT: user space doesn't know "now" in eBPF terms effortlessly.
                            // 
                            // ALTERNATIVE: Use uptime.
                            // `bpf_ktime_get_ns()` returns nanoseconds since boot.
                            // In Rust, we can get uptime from `/proc/uptime` or using `libc`.
                            //
                            // Let's us `nix` or `libc` if available, or just read /proc/uptime for simplicity?
                            // Or better: std::time::Instant::now() is monotonic.
                            // But we need the ABSOLUTE value to compare.
                            //
                            // Let's try reading /proc/uptime.
                            if let Ok(uptime_seconds) = std::fs::read_to_string("/proc/uptime") {
                                if let Some(sec_str) = uptime_seconds.split_whitespace().next() {
                                    if let Ok(sec_f64) = sec_str.parse::<f64>() {
                                        let now_ns = (sec_f64 * 1_000_000_000.0) as u64;
                                        let threshold_ns = now_ns.saturating_sub(180 * 1_000_000_000); // 3 mins ago

                                        // Retrieve keys. HashMap iterator in Aya gives Result<(Key, Value)>.
                                        // We have to be careful about iteration invalidation.
                                        // We collect keys first.
                                        
                                        // Iterate map. Note: This can be slow if map is HUGE, but 10k entries is fine.
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
            }
        });
    }
}
