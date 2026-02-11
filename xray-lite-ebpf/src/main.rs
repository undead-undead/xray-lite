#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    helpers::bpf_ktime_get_ns,
    macros::{classifier, map, xdp},
    maps::HashMap,
    programs::{TcContext, XdpContext},
};
use aya_log_ebpf::warn;
use core::mem;

// --- Map Definitions ---

// Allowed Ports (VLESS ports)
#[map]
static ALLOWED_PORTS: HashMap<u16, u8> = HashMap::with_max_entries(64, 0);

#[derive(Clone, Copy)]
#[repr(C)]
pub struct RateLimitEntry {
    pub last_time_ns: u64,
    pub count: u32,
}

// Track TCP SYN rates for source IPs
#[map]
static RATE_LIMIT_MAP: HashMap<u32, RateLimitEntry> = HashMap::with_max_entries(10240, 0);

// --- Advanced TC Egress Pacing (EDT + Jitter + Bursting) ---
#[derive(Clone, Copy)]
#[repr(C)]
pub struct FlowState {
    pub last_tstamp: u64,
    pub burst_allowance: u64,
}

// BPF Map to store flow state for Pacing
#[map]
static FLOW_STATE_MAP: HashMap<u32, FlowState> = HashMap::with_max_entries(10240, 0);

const TARGET_RATE_BPS: u64 = 500_000_000 / 8; // 500 Mbps (High Performance Mode)
const BURST_SIZE: u64 = 4 * 1024 * 1024; // 4MB Burst (Smooth SABR emulation)

// --- Constants ---
const ETH_P_IP: u16 = 0x0800;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
// CONFIG: Max SYN packets per second per IP
const SYN_LIMIT_PER_SEC: u32 = 50;
const NANOS_PER_SEC: u64 = 1_000_000_000;

// --- Struct Definitions ---

#[repr(C)]
pub struct EthHdr {
    pub dst: [u8; 6],
    pub src: [u8; 6],
    pub etype: u16,
}

#[repr(C)]
pub struct IpHdr {
    pub version_ihl: u8,
    pub tos: u8,
    pub tot_len: u16,
    pub id: u16,
    pub frag_off: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub check: u16,
    pub saddr: u32,
    pub daddr: u32,
}

#[repr(C)]
pub struct TcpHdr {
    pub source: u16,
    pub dest: u16,
    pub seq: u32,
    pub ack_seq: u32,
    pub res1: u8,
    pub flags: u8,
    pub window: u16,
    pub check: u16,
    pub urg_ptr: u16,
}

#[repr(C)]
pub struct UdpHdr {
    pub source: u16,
    pub dest: u16,
    pub len: u16,
    pub check: u16,
}

// --- Logic ---

#[xdp]
pub fn xray_firewall(ctx: XdpContext) -> u32 {
    match try_xdp_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

// --- TC Egress Pacing Logic ---
#[classifier]
pub fn tc_egress_pacing(ctx: TcContext) -> i32 {
    match try_tc_egress_pacing(ctx) {
        Ok(ret) => ret,
        Err(_) => 0, // TC_ACT_OK (Fail open)
    }
}

fn try_tc_egress_pacing(ctx: TcContext) -> Result<i32, ()> {
    let now = unsafe { bpf_ktime_get_ns() };
    let len = ctx.len() as u64;

    // Use Source IP as Flow ID (simplification)
    // In production, use tuple (SrcIP, DstIP, SrcPort, DstPort) hash
    // Here we need to parse headers to get SrcIP, similar to XDP but for SKB
    // Skipping deep packet parsing for brevity, assuming flow_id = 0 for single flow testing
    // or using skb->hash if available.
    // For robust implementation, we'd parse IP header.
    // Let's use a fixed flow ID for global pacing for now to avoid parsing complexity in this snippet
    // or simulate per-flow by just using a single bucket.
    let flow_id: u32 = 0;

    // Calculate transmission time
    let interval_ns = (len * 1_000_000_000) / TARGET_RATE_BPS;

    let mut next_tstamp;

    match FLOW_STATE_MAP.get_ptr_mut(&flow_id) {
        Some(state_ptr) => {
            let state = unsafe { &mut *state_ptr };

            // 1. Burst Logic
            // If idle for a while, allow burst
            if now > state.last_tstamp + interval_ns {
                state.burst_allowance = BURST_SIZE;
            }

            if state.burst_allowance > len {
                state.burst_allowance -= len;
                next_tstamp = now; // Send immediately
            } else {
                // 2. Pacing (Token Bucket / Leaky Bucket)
                next_tstamp = if state.last_tstamp > now {
                    state.last_tstamp + interval_ns
                } else {
                    now + interval_ns
                };

                // 3. Jitter (Randomize +/- 1-3ms to act purely human)
                // Using a simple pseudo-random based on time
                let jitter = (now % 3_000_000) as u64;
                next_tstamp += jitter;
            }
            state.last_tstamp = next_tstamp;
        }
        None => {
            let new_state = FlowState {
                last_tstamp: now + interval_ns,
                burst_allowance: BURST_SIZE,
            };
            let _ = FLOW_STATE_MAP.insert(&flow_id, &new_state, 0);
            next_tstamp = now;
        }
    }

    // Write EDT Timestamp to SKB (Requires FQ qdisc)
    unsafe {
        let skb_ptr: *mut aya_ebpf::bindings::__sk_buff = core::mem::transmute(ctx.skb);
        (*skb_ptr).tstamp = next_tstamp;
    }

    Ok(0) // TC_ACT_OK
}

fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    let start = ctx.data();
    let end = ctx.data_end();

    // 1. Ethernet Header Check
    if start + mem::size_of::<EthHdr>() > end {
        return Ok(xdp_action::XDP_PASS);
    }
    let eth_hdr = unsafe { &*(start as *const EthHdr) };

    // Only handle IPv4
    if eth_hdr.etype != u16::to_be(ETH_P_IP) {
        return Ok(xdp_action::XDP_PASS);
    }

    // 2. IP Header Check
    let ip_start = start + mem::size_of::<EthHdr>();
    if ip_start + mem::size_of::<IpHdr>() > end {
        return Ok(xdp_action::XDP_PASS);
    }
    let ip_hdr = unsafe { &*(ip_start as *const IpHdr) };
    let ihl = ip_hdr.version_ihl & 0x0F;
    let ip_len = (ihl as usize) * 4;
    let trans_start = ip_start + ip_len;

    match ip_hdr.protocol {
        IPPROTO_UDP => {
            if trans_start + mem::size_of::<UdpHdr>() > end {
                return Ok(xdp_action::XDP_PASS);
            }
            let udp_hdr = unsafe { &*(trans_start as *const UdpHdr) };
            let dest_port = u16::from_be(udp_hdr.dest);

            if unsafe { ALLOWED_PORTS.get(&dest_port).is_some() } {
                return Ok(xdp_action::XDP_DROP);
            }
            return Ok(xdp_action::XDP_PASS);
        }
        IPPROTO_TCP => {
            if trans_start + mem::size_of::<TcpHdr>() > end {
                return Ok(xdp_action::XDP_PASS);
            }
            let tcp_hdr = unsafe { &*(trans_start as *const TcpHdr) };
            let dest_port = u16::from_be(tcp_hdr.dest);

            if unsafe { ALLOWED_PORTS.get(&dest_port).is_none() } {
                return Ok(xdp_action::XDP_PASS);
            }

            let flags = tcp_hdr.flags;
            if (flags & 0x03) == 0x03 {
                return Ok(xdp_action::XDP_DROP);
            }
            if (flags & 0x06) == 0x06 {
                return Ok(xdp_action::XDP_DROP);
            }

            if (flags & 0x02 != 0) && (flags & 0x10 == 0) {
                let src_ip = u32::from_be(ip_hdr.saddr);
                let now = unsafe { bpf_ktime_get_ns() };

                match RATE_LIMIT_MAP.get_ptr_mut(&src_ip) {
                    Some(entry) => {
                        let entry = unsafe { &mut *entry };
                        if now > entry.last_time_ns + NANOS_PER_SEC {
                            entry.last_time_ns = now;
                            entry.count = 1;
                        } else {
                            entry.count += 1;
                            if entry.count > SYN_LIMIT_PER_SEC {
                                if entry.count % 100 == 0 {
                                    warn!(
                                        &ctx,
                                        "⛔ RATELIMIT: Dropped SYN flood from IP {:x}", src_ip
                                    );
                                }
                                return Ok(xdp_action::XDP_DROP);
                            }
                        }
                    }
                    None => {
                        let new_entry = RateLimitEntry {
                            last_time_ns: now,
                            count: 1,
                        };
                        let _ = RATE_LIMIT_MAP.insert(&src_ip, &new_entry, 0);
                    }
                }
            }
            return Ok(xdp_action::XDP_PASS);
        }
        _ => return Ok(xdp_action::XDP_PASS),
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
