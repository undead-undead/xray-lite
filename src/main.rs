use anyhow::Result;
use clap::Parser;
use tracing::{info, Level, error};
use tracing_subscriber;

mod config;
mod network;
mod protocol;
mod server;
mod transport;
mod utils;
mod handler;
mod xdp;
mod server_uring;

use crate::config::Config;
use crate::server::Server;

#[cfg(not(target_os = "windows"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[derive(Parser, Debug)]
#[command(author, version = env!("CARGO_PKG_VERSION"), about, long_about = None)]
struct Args {
    /// 配置文件路径
    #[arg(short, long, default_value = "config.json")]
    config: String,

    /// 日志级别
    #[arg(short, long, default_value = "info")]
    log_level: String,

    /// 启用 XDP 内核级 TLS 预过滤 (Need Root + Kernel 5.4+)
    #[arg(long, default_value_t = false)]
    enable_xdp: bool,

    /// XDP 绑定的网卡接口 (e.g., eth0)
    #[arg(long, default_value = "eth0")]
    xdp_iface: String,

    /// 启用 io_uring 高性能运行时 (Linux 5.10+)
    #[arg(long, default_value_t = false)]
    uring: bool,
}

fn main() -> Result<()> {
    // 提高文件句柄限制 (Linux)
    #[cfg(not(target_os = "windows"))]
    {
        let mut limit = libc::rlimit {
            rlim_cur: 65535,
            rlim_max: 65535,
        };
        unsafe {
            if libc::setrlimit(libc::RLIMIT_NOFILE, &limit) != 0 {
                limit.rlim_cur = 4096;
                limit.rlim_max = 4096;
                libc::setrlimit(libc::RLIMIT_NOFILE, &limit);
            }
        }
    }

    let args = Args::parse();
    
    if args.uring {
        info!("⚡ Using high-efficiency io_uring mode");
        use crate::utils::task::{set_runtime_mode, RuntimeMode};
        
        monoio::start::<monoio::FusionDriver, _>(async move {
            set_runtime_mode(RuntimeMode::Monoio);
            async_main(args).await
        })
    } else {
        info!("🧵 Using standard Tokio mode");
        use crate::utils::task::{set_runtime_mode, RuntimeMode};
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        rt.block_on(async move {
            set_runtime_mode(RuntimeMode::Tokio);
            let local = tokio::task::LocalSet::new();
            local.run_until(async_main(args)).await
        })
    }
}

async fn async_main(args: Args) -> Result<()> {
    let log_level_str = std::env::var("RUST_LOG").unwrap_or_else(|_| args.log_level.clone());
    let log_level = match log_level_str.to_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };

    tracing_subscriber::fmt().with_max_level(log_level).with_target(false).init();

    info!("🚀 Xray-Lite v0.6.0-beta1 [io_uring native]");
    let config = Config::load(&args.config)?;
    info!("✅ Configuration loaded successfully");

    // Extract ports for XDP
    let mut protected_ports = Vec::new();
    for inbound in &config.inbounds {
        protected_ports.push(inbound.port);
    }

    if args.enable_xdp || std::env::var("XRAY_XDP_ENABLE").is_ok() {
        #[cfg(feature = "xdp")]
        {
            let iface = std::env::var("XRAY_XDP_IFACE").unwrap_or(args.xdp_iface);
            info!("🔥 Attempting to load XDP Firewall on interface: {}", iface);
            xdp::loader::start_xdp(&iface, protected_ports);
        }
        #[cfg(not(feature = "xdp"))]
        {
            tracing::warn!("⚠️  XDP was requested, but this binary was NOT compiled with XDP support.");
        }
    }

    if args.uring {
        let server = crate::server_uring::UringServer::new(config)?;
        server.run().await?;
    } else {
        let server = Server::new(config)?;
        server.run().await?;
    }

    Ok(())
}
