use anyhow::Result;
use clap::Parser;
use tracing::{info, Level};
use tracing_subscriber;

mod config;
mod network;
mod protocol;
mod server;
mod transport;
mod utils;

use crate::config::Config;
use crate::server::Server;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// 配置文件路径
    #[arg(short, long, default_value = "config.json")]
    config: String,

    /// 日志级别
    #[arg(short, long, default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // 初始化日志
    // 优先使用环境变量 RUST_LOG，否则使用命令行参数
    let log_level_str = std::env::var("RUST_LOG")
        .unwrap_or_else(|_| args.log_level.clone());
    
    let log_level = match log_level_str.to_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };

    tracing_subscriber::fmt()
        .with_max_level(log_level)
        .with_target(false)
        .with_thread_ids(true)
        .init();

    info!("🚀 Starting VLESS+Reality+XHTTP Server [V35-CONFIG]");
    info!("📄 Loading config from: {}", args.config);

    // 加载配置
    let config = Config::load(&args.config)?;
    info!("✅ Configuration loaded successfully");

    // 创建并启动服务器
    let server = Server::new(config)?;
    info!("🌐 Server initialized");

    // 运行服务器
    server.run().await?;

    Ok(())
}
