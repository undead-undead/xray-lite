# Xray-lite XDP & TC Features

## Kernel-Level Stealth & Performance
Xray-lite leverages the latest Linux eBPF technology (XDP and TC) to provide a paradigm shift in proxy security and performance. By offloading critical security and traffic shaping logic to the kernel, we achieve sub-microsecond latency and hardware-like stealth that is impossible for traditional user-space proxies.

## Key Subsystems

### 1. XDP Adaptive Firewall (Layer 2)
The XDP (eXpress Data Path) firewall acts as the first line of defense, processing packets directly at the network driver level.
- **Anti-Probing**: Automatically drops non-TLS traffic and suspicious probing attempts before they even reach the application layer.
- **DDoS Mitigation**: High-performance SYN-flood protection and rate limiting processed with near-zero CPU overhead.
- **Dynamic Port Protection**: Only specifically allowed protocol ports are exposed, making the server invisible to port scanners.
- **Auto-GC State Management**: Intelligent garbage collection for eBPF maps ensures long-term stability without resource exhaustion.

### 2. TC-BPF Pacing: EDT + Jitter + Bursting (Layer 3)
Traditional traffic shaping often uses simple token buckets that create a "robotic" pattern. Xray-lite uses a sophisticated **TC-BPF Egress Pacing** engine based on **Earliest Departure Time (EDT)**.

- **EDT (Earliest Departure Time)**: Instead of just limiting rate, we calculate precise timestamps for each packet to be transmitted, forcing a strict yet high-performance delivery schedule.
- **Human-Like Jitter**: Injects micro-randomized delays (1-3ms) into the packet schedule. This eliminates the mathematical periodicity that modern GFW sensors look for.
- **Adaptive Bursting**: Allows small bursts of high-speed data followed by a controlled "cool-down" period, perfectly mimicking the behavior of organic human web browsing and video streaming.
- **Kernel-level Timing**: By scheduling packets at the TC layer, we bypass user-space scheduling jitter, ensuring the traffic profile matches your mimicry target (e.g., Chrome or video apps) with microsecond precision.

### 3. Collaborative Defense (The Shredder Meta)
- **Layer 3 (TC-BPF)**: Shapes the **timing** and **cadence** of the traffic using EDT.
- **Layer 7 (xhttp Shredder)**: Shapes the **size** and **structure** of the packets via HTTP/2 stream multiplexing and adaptive padding.
This multi-layer approach ensures that both your traffic's **timing signature** and **size distribution** are perfectly cloaked.

## Hardware Requirements
- **Kernel 5.8+**: Recommended for advanced TC-BPF and BPF_MAP_TYPE_HASH.
- **Privileged Access**: `CAP_NET_ADMIN` and `CAP_SYS_ADMIN` are required to load eBPF programs.
- **Supported Architectures**: x86_64, arm64.
