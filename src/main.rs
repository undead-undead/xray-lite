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

    /// 启用高性能 io_uring 模式 (Requires Linux 5.10+)
    #[arg(long, default_value_t = false)]
    uring: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();
    
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

    if args.uring {
        info!("⚡ Starting in high-efficiency io_uring mode");
        use crate::utils::task::{set_runtime_mode, RuntimeMode};
        
        // Use FusionDriver for better balance on 1-vCPU KVM
        let mut rt = monoio::RuntimeBuilder::<monoio::FusionDriver>::new()
            .enable_timer()
            .with_entries(1024) 
            .build()
            .expect("Failed to build monoio runtime");

        // Pin to ensure low context-switch overhead
        if let Some(core_ids) = core_affinity::get_core_ids() {
            if !core_ids.is_empty() {
                core_affinity::set_for_current(core_ids[0]);
                info!("📌 Affinity set to Core 0");
            }
        }

        rt.block_on(async move {
            set_runtime_mode(RuntimeMode::Monoio);
            async_main(args).await
        })
    } else {
        info!("🧵 Starting in standard Tokio mode");
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

    info!("🚀 Xray-Lite v0.4.6-stable [io_uring optimized]");
    let config = Config::load(&args.config)?;
    info!("✅ Configuration loaded successfully");

    if args.uring {
        let server = crate::server_uring::UringServer::new(config)?;
        server.run().await?;
    } else {
        let server = Server::new(config)?;
        server.run().await?;
    }

    Ok(())
}
