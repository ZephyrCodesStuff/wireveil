use anyhow::{Context, Result};
use figment::{
    providers::{Format, Toml},
    Figment,
};
use nfqueue::{CopyMode, Queue};
use nft::NFT_QUEUE_SESSION;
use std::path::Path;
use tokio::runtime::Runtime;
use tracing::{debug, error, info, level_filters::LevelFilter};
use tracing_subscriber::{EnvFilter, FmtSubscriber};

mod http;
mod nft;
mod structs;

use structs::{config::Config, state::State};

fn main() -> Result<()> {
    // Initialize dotenv
    dotenv::dotenv().ok();

    // Set up structured logging with environment variable control
    let filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();

    let subscriber = FmtSubscriber::builder()
        .with_env_filter(filter)
        .with_target(true) // Include target module in logs
        .with_thread_ids(true) // Include thread IDs for better debugging
        .with_file(true) // Include file information
        .with_line_number(true) // Include line numbers
        .compact() // Use compact format
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .context("Failed to set up global tracing subscriber")?;

    // Ensure the user is running as root (iptables requires it)
    if !nix::unistd::Uid::effective().is_root() {
        error!("⛔ WireVeil must be run as root");
        return Err(anyhow::anyhow!("WireVeil must be run as root"));
    }

    info!("🛡️ WireVeil firewall starting up");

    // Load configuration from wireveil.toml
    let config_path = "wireveil.toml";
    if !Path::new(config_path).exists() {
        error!("⛔ Configuration file '{}' not found", config_path);

        return Err(anyhow::anyhow!(
            "Configuration file '{}' not found",
            config_path
        ));
    }

    let config: Config = Figment::new()
        .merge(Toml::file(config_path))
        .extract()
        .context(format!(
            "Failed to parse configuration file '{config_path}'",
        ))?;

    // Log the loaded configuration
    info!(
        services_count = config.services.len(),
        "📋 Configuration loaded"
    );

    for (name, service) in &config.services {
        info!(
            service = %name,
            port = service.port,
            rules_count = service.block.len(),
            "🔍 Service configured"
        );

        // Log the actual rules at debug level for security operators
        for (i, rule) in service.block.iter().enumerate() {
            debug!(
                service = %name,
                port = service.port,
                rule_index = i,
                pattern = %rule,
                "Rule pattern registered"
            );
        }
    }

    // Set up iptables rules
    nft::setup(&config).context("Failed to set up iptables rules")?;
    info!("🔧 iptables rules configured");

    // Set up signal handling for cleanup on exit
    let runtime = Runtime::new().context("Failed to create tokio runtime")?;
    runtime.block_on(async {
        tokio::spawn(async {
            tokio::signal::ctrl_c()
                .await
                .expect("Failed to listen for ctrl+c");
            info!("⏹️ Shutdown signal received, cleaning up");

            if let Err(e) = nft::cleanup() {
                error!("Failed to clean up: {e:#}!")
            }

            std::process::exit(0);
        });
    });

    // Initialize nfqueue
    let Ok(mut q) = Queue::new(State::new(&config)) else {
        error!("Failed to open queue!");
        return Err(anyhow::anyhow!("Failed to open netfilter queue!"));
    };

    info!("✅ WireVeil firewall initialization complete");

    q.unbind(libc::AF_INET);

    let rc = q.bind(libc::AF_INET);
    if rc != 0 {
        return Err(anyhow::anyhow!(
            "Failed to bind to AF_INET with error code: {}",
            rc
        ));
    }

    let Some(queue) = NFT_QUEUE_SESSION.get() else {
        error!("Failed to retrieve queue!");
        return Err(anyhow::anyhow!("Failed to retrieve netfilter queue!"));
    };

    q.create_queue(*queue, nft::queue_callback);
    q.set_mode(CopyMode::CopyPacket, u16::MAX as u32);

    info!("🚀 NFQueue initialized and ready to process packets");
    q.run_loop();

    Ok(())
}
