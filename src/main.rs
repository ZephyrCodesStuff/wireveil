use anyhow::{Context, Result};
use etherparse::{SlicedPacket, TransportSlice};
use figment::{
    Figment,
    providers::{Format, Toml},
};
use libc;
use nfqueue::{CopyMode, Message, Queue, Verdict};
use std::path::Path;
use tokio::runtime::Runtime;
use tracing::{debug, error, info, level_filters::LevelFilter, trace};
use tracing_subscriber::{EnvFilter, FmtSubscriber};

mod http_parser;
mod iptables;
mod structs;

use structs::{config::Config, state::State};

const CHAIN_NAME: &str = "WIREVEIL";
const QUEUE_IDX: u16 = 1;

fn queue_callback(msg: &Message, state: &mut State) {
    // Initialize the state
    state.count += 1;

    // Parse the packet and get the payload
    let Ok(packet) = SlicedPacket::from_ip(msg.get_payload()) else {
        debug!(id = state.count, "Failed to parse packet");
        msg.set_verdict(Verdict::Accept); // Play it safe
        return;
    };

    let Some(transport) = packet.transport else {
        debug!(id = state.count, "Packet has no transport information");
        msg.set_verdict(Verdict::Accept); // Play it safe
        return;
    };

    // We're only processing TCP packets
    let tcp = match transport {
        TransportSlice::Tcp(tcp) => tcp,
        _ => {
            debug!(id = state.count, transport_type = ?transport, "Non-TCP packet accepted");
            msg.set_verdict(Verdict::Accept); // Play it safe
            return;
        }
    };

    // Extract source and destination information for better logging
    let src_port = tcp.source_port();
    let dst_port = tcp.destination_port();
    let src_addr = packet
        .net
        .and_then(|net| {
            net.ipv4_ref()
                .map(|ipv4| ipv4.header().source_addr().to_string())
        })
        .unwrap_or_else(|| "unknown".to_string());

    // Get the payload as bytes
    let payload = tcp.payload();

    // Create a default content string from payload
    let content = String::from_utf8_lossy(payload).to_string();

    trace!(
        id = state.count,
        src = %src_addr,
        sport = src_port,
        dport = dst_port,
        payload_size = payload.len(),
        "Received TCP packet"
    );

    // Try to detect and process HTTP content
    let normalized_url = if is_http_traffic(dst_port) {
        debug!(
            id = state.count,
            src = %src_addr,
            sport = src_port,
            dport = dst_port,
            "Potential HTTP traffic detected"
        );

        // Process HTTP packet and extract normalized URL if it's HTTP
        let http_content = http_parser::process_http_packet(payload);

        if let Some(url) = http_content {
            debug!(
                id = state.count,
                src = %src_addr,
                url = %url,
                "HTTP URL normalized"
            );
            // For HTTP traffic, we'll check both the raw content and the normalized URL
            Some(url)
        } else {
            trace!(id = state.count, "Not HTTP or failed to extract URL");
            None
        }
    } else {
        None
    };

    // Check if we have rules for this port
    if let Some(rules) = state.service_rules.get(&dst_port) {
        // Check all regex rules for this port
        for regex in rules {
            // First check the raw content
            let content_match = regex.is_match(&content);

            // Then check the normalized URL if it exists
            let url_match = normalized_url
                .as_ref()
                .map_or(false, |url| regex.is_match(url));

            if content_match || url_match {
                // Create a formatted hex representation for logging
                let content_hex = content
                    .as_bytes()
                    .iter()
                    .map(|b| format!("{:02X}", b))
                    .collect::<Vec<String>>()
                    .join(" ");

                // Use different log formats for different match types
                if content_match && url_match {
                    error!(
                        id = state.count,
                        src_ip = %src_addr,
                        src_port = src_port,
                        dst_port = dst_port,
                        rule = %regex.as_str(),
                        match_type = "both raw and normalized",
                        normalized_url = %normalized_url.as_ref().unwrap(),
                        "🚫 BLOCKED: Packet matched filter in both raw and normalized form"
                    );
                } else if url_match {
                    error!(
                        id = state.count,
                        src_ip = %src_addr,
                        src_port = src_port,
                        dst_port = dst_port,
                        rule = %regex.as_str(),
                        match_type = "normalized only",
                        normalized_url = %normalized_url.as_ref().unwrap(),
                        "🚫 BLOCKED: Packet matched filter only after URL normalization"
                    );
                } else {
                    error!(
                        id = state.count,
                        src_ip = %src_addr,
                        src_port = src_port,
                        dst_port = dst_port,
                        rule = %regex.as_str(),
                        match_type = "raw only",
                        "🚫 BLOCKED: Packet matched filter in raw form"
                    );
                }

                // Log detailed packet information at debug level
                debug!(
                    id = state.count,
                    payload = %content,
                    hex = %content_hex,
                    "Blocked packet details"
                );

                msg.set_verdict(Verdict::Drop);
                return;
            }
        }
    }

    // No matching rules, accept the packet
    trace!(
        id = state.count,
        src = %src_addr,
        sport = src_port,
        dport = dst_port,
        "Accepting packet"
    );
    msg.set_verdict(Verdict::Accept);
}

// Function to determine if a port is typically used for HTTP traffic
fn is_http_traffic(port: u16) -> bool {
    // Common HTTP/HTTPS ports
    matches!(
        port,
        80 | 443 | 8000 | 8080 | 8443 | 3000 | 4000 | 8888 | 9000
    )
}

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
            "Failed to parse configuration file '{}'",
            config_path
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
    iptables::setup(&config).context("Failed to set up iptables rules")?;
    info!("🔧 iptables rules configured");

    // Set up signal handling for cleanup on exit
    let runtime = Runtime::new().context("Failed to create tokio runtime")?;
    let _ = runtime.block_on(async {
        tokio::spawn(async {
            tokio::signal::ctrl_c()
                .await
                .expect("Failed to listen for ctrl+c");
            info!("⏹️ Shutdown signal received, cleaning up");
            if let Err(e) = iptables::cleanup() {
                error!(error = %e, "Failed to clean up iptables rules");
            }
            std::process::exit(0);
        });
    });

    // Initialize nfqueue
    let mut q = Queue::new(State::new(&config));
    q.open();

    info!("✅ WireVeil firewall initialization complete");

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

    info!("🚀 NFQueue initialized and ready to process packets");
    q.run_loop();

    // Cleanup on normal exit
    if let Err(e) = iptables::cleanup() {
        error!(error = %e, "Failed to clean up iptables rules");
    }

    Ok(())
}
