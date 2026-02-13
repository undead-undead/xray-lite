#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

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

#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub struct RateLimitEntry {
    pub last_time_ns: u64,
    pub count: u64,
}

// Track TCP SYN rates for source IPs
#[map]
static RATE_LIMIT_MAP: HashMap<u32, RateLimitEntry> = HashMap::with_max_entries(10240, 0);

// --- Advanced TC Egress Pacing (EDT + Jitter + Bursting) ---
#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub struct FlowState {
    pub last_tstamp: u64,
    pub burst_allowance: u64,
}

// BPF Map to store flow state for Pacing
#[map]
static FLOW_STATE_MAP: HashMap<u32, FlowState> = HashMap::with_max_entries(10240, 0);

const TARGET_RATE_BPS: u64 = 500_000_000 / 8; // 500 Mbps (High Performance Mode)
const BURST_SIZE: u64 = 2 * 1024 * 1024; // 2MB Burst (Better for 4K & Gigabit)

// --- Constants ---
const ETH_P_IP: u16 = 0x0800;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
// CONFIG: Max SYN packets per second per IP
const SYN_LIMIT_PER_SEC: u32 = 10000; // Relaxed to 10000 to prevent blocking legitimate bursts (YouTube/QUIC)
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

    // 1. Get raw SKB pointer (Transmute ctx.skb once to avoid Move errors)
    let skb_ptr: *mut aya_ebpf::bindings::__sk_buff = unsafe { core::mem::transmute(ctx.skb) };

    // 2. Read existing timestamp
    let mut tstamp = unsafe { (*skb_ptr).tstamp };

    // 3. Micro-Jitter Logic
    // Only apply jitter if BBR has already set a pacing time.
    if tstamp != 0 {
        // Generate random jitter: 0 ~ 500 microseconds (0.5ms)
        // 0.5ms is small enough to be ignored by BBR's RTT filter,
        // but large enough to randomize Inter-Arrival Time for DPI.
        let jitter_ns = (unsafe { aya_ebpf::helpers::bpf_get_prandom_u32() } % 500_000) as u64;

        // Apply jitter, ensuring we don't accidentally schedule into the past relative to now
        // (though FQ handles past timestamps by sending immediately)
        if tstamp > now {
            tstamp += jitter_ns;
        } else {
            tstamp = now + jitter_ns;
        }
    } else {
        // Non-TCP or CUBIC traffic (no pacing set): Send immediately
        // We do NOT delay these packets to avoid latency spikes on ACKs/DNS.
        tstamp = now;
    }

    // 4. Write modified timestamp back to SKB
    unsafe {
        (*skb_ptr).tstamp = tstamp;
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
                return Ok(xdp_action::XDP_PASS); // FIX: Was DROP, must be PASS
            }
            // Block other UDP (QUIC/DNS amplification protection)
            return Ok(xdp_action::XDP_DROP);
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
                    Some(entry_ptr) => {
                        let entry = unsafe { &mut *entry_ptr };
                        let last_time = entry.last_time_ns;
                        let count = entry.count;

                        if now > last_time + NANOS_PER_SEC {
                            unsafe {
                                core::ptr::write_volatile(&mut entry.last_time_ns, now);
                                core::ptr::write_volatile(&mut entry.count, 1u64);
                            }
                        } else {
                            let new_count = count + 1;
                            unsafe {
                                core::ptr::write_volatile(&mut entry.count, new_count);
                            }

                            if new_count > SYN_LIMIT_PER_SEC as u64 {
                                if new_count % 100 == 0 {
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
                        let mut data = [0u64; 2];
                        let now_val = now;
                        let p = data.as_mut_ptr();

                        unsafe {
                            // Golden Version Strategy: Magic Numbers (0xDEAD)
                            core::arch::asm!(
                                "*(u64 *)({0} + 0) = {1}",
                                "*(u32 *)({0} + 8) = 0xDE",   // Magic Low
                                "*(u32 *)({0} + 12) = 0xAD",  // Magic High (Padding)
                                in(reg) p,
                                in(reg) now_val,
                            );

                            // Direct helper call using the physical pointer
                            aya_ebpf::helpers::bpf_map_update_elem(
                                &RATE_LIMIT_MAP as *const _ as *mut _,
                                &src_ip as *const _ as *const _,
                                data.as_ptr() as *const _ as *const _,
                                0,
                            );
                        }
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
