use anyhow::{Context, Result};
use etherparse::{SlicedPacket, TransportSlice};
use figment::{
    Figment,
    providers::{Format, Toml},
};
use libc;
use nfqueue::{CopyMode, Message, Queue, Verdict};
use regex::Regex;
use std::path::Path;
use std::{collections::HashMap, net::Ipv4Addr};
use tokio::runtime::Runtime;
use tracing::{debug, error, info, level_filters::LevelFilter, trace};
use tracing_subscriber::{EnvFilter, FmtSubscriber};

mod iptables;
mod structs;

use structs::config::Config;

const CHAIN_NAME: &str = "WIREVEIL";
const QUEUE_IDX: u16 = 1;

struct State {
    count: u32,
    service_rules: HashMap<u16, Vec<Regex>>,
}

impl State {
    pub fn new(config: &Config) -> State {
        let mut service_rules = HashMap::new();

        // Compile all regex patterns for efficient packet processing
        for (service_name, service) in &config.services {
            let compiled_rules = service
                .block
                .iter()
                .filter_map(|pattern| match Regex::new(pattern) {
                    Ok(regex) => Some(regex),
                    Err(e) => {
                        error!(
                            "Failed to compile regex pattern '{}' for service {}: {}",
                            pattern, service_name, e
                        );
                        None
                    }
                })
                .collect();

            service_rules.insert(service.port, compiled_rules);
        }

        State {
            count: 0,
            service_rules,
        }
    }
}

fn queue_callback(msg: &Message, state: &mut State) {
    // Initialize the state
    state.count += 1;

    // Parse the packet and get the payload
    let Ok(packet) = SlicedPacket::from_ip(msg.get_payload()) else {
        debug!("[{}] Failed to parse packet", state.count);
        msg.set_verdict(Verdict::Accept); // Play it safe
        return;
    };

    let Some(transport) = packet.transport else {
        debug!("[{}] Packet has no transport information", state.count);
        msg.set_verdict(Verdict::Accept); // Play it safe
        return;
    };

    // We're only processing TCP packets
    let tcp = match transport {
        TransportSlice::Tcp(tcp) => tcp,
        _ => {
            debug!("[{}] Packet is not TCP", state.count);
            msg.set_verdict(Verdict::Accept); // Play it safe
            return;
        }
    };

    // Get the actual content
    let content = String::from_utf8_lossy(&tcp.payload());

    trace!(
        content = content.to_string(),
        "[{}] Received TCP packet", state.count,
    );

    // Check if we have rules for this port
    if let Some(rules) = state.service_rules.get(&tcp.destination_port()) {
        // Check all regex rules for this port
        for regex in rules {
            if regex.is_match(&content) {
                // Try to get sender
                let sender = packet
                    .net
                    .map(|net| net.ipv4_ref().map(|ipv4| ipv4.header().source_addr()))
                    .flatten()
                    .or_else(|| Some(Ipv4Addr::UNSPECIFIED))
                    .map(|ipv4| ipv4.to_string());

                let content = content.to_string();
                let content_hex = content
                    .as_bytes()
                    .iter()
                    .map(|b| format!("{:02X}", b))
                    .collect::<Vec<String>>()
                    .join(" ");

                error!(
                    sender,
                    port = tcp.destination_port(),
                    blocked_by = regex.as_str(),
                    "[{}] [!] Dropping packet based on rule match",
                    state.count,
                );

                debug!(
                    payload = content,
                    bytes = content_hex,
                    "[{}] [!] Offending packet",
                    state.count,
                );

                msg.set_verdict(Verdict::Drop);
                return;
            }
        }
    }

    // No matching rules, accept the packet
    trace!(
        port = tcp.destination_port(),
        "[{}] Accepting packet", state.count
    );
    msg.set_verdict(Verdict::Accept);
}

fn main() -> Result<()> {
    // Initialize dotenv
    dotenv::dotenv().ok();

    let filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();

    let subscriber = FmtSubscriber::builder()
        .with_env_filter(filter)
        .compact()
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .context("Failed to set up global tracing subscriber")?;

    info!("WireVeil firewall starting up");

    // Load configuration from wireveil.toml
    let config_path = "wireveil.toml";
    if !Path::new(config_path).exists() {
        error!("Configuration file '{}' not found", config_path);

        return Err(anyhow::anyhow!(
            "Configuration file '{}' not found",
            config_path
        ));
    }

    let config: Config = Figment::new()
        .merge(Toml::file(config_path))
        .extract()
        .context(format!(
            "Failed to parse configuration file '{}'",
            config_path
        ))?;

    // Log the loaded configuration
    info!(
        "Loaded configuration with {} services",
        config.services.len()
    );
    for (name, service) in &config.services {
        info!(
            service = name,
            port = service.port,
            rules = service.block.len(),
            "Service configured"
        );
    }

    // Set up iptables rules
    iptables::setup(&config).context("Failed to set up iptables rules")?;

    // Set up signal handling for cleanup on exit
    let runtime = Runtime::new().context("Failed to create tokio runtime")?;
    let _ = runtime.block_on(async {
        tokio::spawn(async {
            tokio::signal::ctrl_c()
                .await
                .expect("Failed to listen for ctrl+c");
            info!("Shutdown signal received, cleaning up");
            if let Err(e) = iptables::cleanup() {
                error!("Failed to clean up iptables rules: {}", e);
            }
            std::process::exit(0);
        });
    });

    // Initialize nfqueue
    let mut q = Queue::new(State::new(&config));
    q.open();

    info!("WireVeil firewall initialization complete");

    q.unbind(libc::AF_INET);

    let rc = q.bind(libc::AF_INET);
    if rc != 0 {
        return Err(anyhow::anyhow!(
            "Failed to bind to AF_INET with error code: {}",
            rc
        ));
    }

    q.create_queue(QUEUE_IDX, queue_callback);
    q.set_mode(CopyMode::CopyPacket, 0xffff);

    info!("NFQueue initialized and ready to process packets");
    q.run_loop();

    // Cleanup on normal exit
    if let Err(e) = iptables::cleanup() {
        error!("Failed to clean up iptables rules: {}", e);
    }

    Ok(())
}
