use std::{ffi::CString, sync::OnceLock};

use anyhow::Result;
use etherparse::{SlicedPacket, TransportSlice};
use nfqueue::{Message, Verdict};
use nftnl::{
    self,
    expr::{self, Expression},
    nft_expr, Batch, Chain, ChainType, Hook, MsgType, Policy, ProtoFamily, Rule, Table,
};
use rand::RngCore;
use tracing::{debug, error, info, trace};

use crate::structs::{config::Config, state::State};

const NFT_TABLE_NAME: &str = "WIREVEIL";
const NFT_CHAIN_NAME: &str = "SERVICES";

/// A randomly generated table name for the current session
///
/// This avoids conflicts and overlaps
pub static NFT_TABLE_NAME_SESSION: OnceLock<CString> = OnceLock::new();

/// A randomly generated queue number for the current session
pub static NFT_QUEUE_SESSION: OnceLock<u16> = OnceLock::new();

// NOTE: `Verdict::Queue` does exist, but it doesn't allow us
//       to pick a custom queue number. This does.
pub struct QueueRule {
    queue_number: u16,
}

impl Expression for QueueRule {
    fn to_expr(&self, _: &Rule) -> *mut nftnl_sys::nftnl_expr {
        // Create a queue expression
        let queue_name = CString::new("queue").unwrap();
        let expr = unsafe { nftnl_sys::nftnl_expr_alloc(queue_name.as_ptr()) };

        if expr.is_null() {
            panic!("Failed to allocate queue expression");
        }

        // Set queue number to 0
        unsafe {
            nftnl_sys::nftnl_expr_set_u16(
                expr,
                nftnl_sys::NFTNL_EXPR_QUEUE_NUM as u16,
                self.queue_number,
            )
        };

        expr
    }
}

pub fn setup(config: &Config) -> Result<()> {
    info!("Setting up nftables rules using nftnl...");

    // Create a new batch for atomic rule updates
    let mut batch = Batch::new();

    // Generate a random table name
    let mut random_bytes = [0u8; 8];
    rand::rng().fill_bytes(&mut random_bytes);
    let random_table_suffix = random_bytes
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<String>();
    let table_name_str = format!("{}-{}", NFT_TABLE_NAME, random_table_suffix);
    let table_name_cstring = CString::new(table_name_str.as_str()).unwrap();

    // Set the OnceLock to our generated name
    if NFT_TABLE_NAME_SESSION.set(table_name_cstring).is_err() {
        error!("Failed to generate a session name!");
        return Err(anyhow::anyhow!("Failed to generate a session name!"));
    }

    // Generate a random queue number
    let random_queue: u16 = rand::random();
    if NFT_QUEUE_SESSION.set(random_queue).is_err() {
        error!("Failed to generate a queue number!");
        return Err(anyhow::anyhow!("Failed to generate a queue number!"));
    }

    // Create the filter table
    let table = Table::new(&NFT_TABLE_NAME_SESSION.get().unwrap(), ProtoFamily::Inet);
    batch.add(&table, MsgType::Add);

    // Create our custom chain for the firewall rules
    let chain_name: CString = CString::new(NFT_CHAIN_NAME).unwrap();
    let chain = Chain::new(&chain_name, &table);
    batch.add(&chain, MsgType::Add);

    // Create INPUT chain
    let input_chain_name = CString::new("INPUT").unwrap();
    let mut input_chain = Chain::new(&input_chain_name, &table);
    input_chain.set_hook(Hook::In, 0);
    input_chain.set_type(ChainType::Filter);
    input_chain.set_policy(Policy::Accept);
    batch.add(&input_chain, MsgType::Add);

    // Add a jump rule from INPUT to our WIREVEIL chain
    let mut jump_rule = Rule::new(&input_chain);

    // Jump to our WIREVEIL chain
    jump_rule.add_expr(&expr::Verdict::Jump {
        chain: chain.get_name().into(),
    });
    batch.add(&jump_rule, MsgType::Add);

    // For each configured service, add a rule to redirect to NFQueue
    for (service_name, service) in &config.services {
        info!(
            service = %service_name,
            port = service.port,
            rules_count = service.block.len(),
            "Setting up nftables rule for service"
        );

        // Create a rule matching the service port
        let mut rule = Rule::new(&chain);

        // Match IPv4 protocol TCP
        rule.add_expr(&nft_expr!(meta l4proto));
        rule.add_expr(&nft_expr!(cmp == libc::IPPROTO_TCP));

        // Match destination port
        rule.add_expr(&nft_expr!(payload tcp dport));
        // CRITICAL: invert the byte order (this is a bug in `nftnl`!)
        rule.add_expr(&nft_expr!(cmp == service.port.swap_bytes()));

        // Add counter for monitoring
        rule.add_expr(&nft_expr!(counter));

        // Send to NFQueue
        rule.add_expr(&QueueRule {
            queue_number: *NFT_QUEUE_SESSION.get().expect("Failed to get NFT queue!"),
        });

        // Add the rule to the batch
        batch.add(&rule, MsgType::Add);

        debug!(
            service = %service_name,
            port = service.port,
            "Added rule to redirect traffic to NFQueue"
        );
    }

    // Finalize and send the batch
    let finalized_batch = batch.finalize();
    send_batch_to_kernel(&finalized_batch)?;

    info!("🔧 nftables rules configured");
    Ok(())
}

pub fn cleanup() -> Result<()> {
    // Create a new batch for atomic rule updates
    let mut batch = Batch::new();

    // Create the filter table
    let Some(table_name) = NFT_TABLE_NAME_SESSION.get() else {
        error!("Failed to retrieve the session name!");
        return Err(anyhow::anyhow!("Failed to retrieve the session name!"));
    };
    let table = Table::new(&table_name, ProtoFamily::Inet);

    // Remove the table
    batch.add(&table, MsgType::Del);

    // Finalize and send the batch
    let finalized_batch = batch.finalize();
    send_batch_to_kernel(&finalized_batch)?;

    info!("🔧 nftables rules deleted");

    Ok(())
}

fn send_batch_to_kernel(batch: &nftnl::FinalizedBatch) -> Result<()> {
    // Create a netlink socket to netfilter
    let socket = mnl::Socket::new(mnl::Bus::Netfilter)?;

    // Send all the bytes in the batch
    socket.send_all(batch)?;

    // Process any response messages
    let portid = socket.portid();
    let mut buffer = vec![0; nftnl::nft_nlmsg_maxsize() as usize];

    while let Some(message) = recv_socket_message(&socket, &mut buffer)? {
        debug!("Received message from kernel: {:?}", message);

        match mnl::cb_run(message, 2, portid)? {
            mnl::CbResult::Stop => break,
            mnl::CbResult::Ok => (),
        }
    }

    Ok(())
}

fn recv_socket_message<'a>(socket: &mnl::Socket, buf: &'a mut [u8]) -> Result<Option<&'a [u8]>> {
    let ret = socket.recv(buf)?;
    if ret > 0 {
        Ok(Some(&buf[..ret]))
    } else {
        Ok(None)
    }
}

pub fn queue_callback(msg: &Message, state: &mut State) {
    // Initialize the state
    state.count += 1;

    // Check if the packet is completely empty
    if msg.get_payload().len() == 0 {
        debug!(id = state.count, "Packet is empty!");
        msg.set_verdict(Verdict::Accept); // Play it safe
        return;
    }

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
    let normalized_url = if crate::http::is_http_traffic(dst_port) {
        debug!(
            id = state.count,
            src = %src_addr,
            sport = src_port,
            dport = dst_port,
            "Potential HTTP traffic detected"
        );

        // Process HTTP packet and extract normalized URL if it's HTTP
        let http_content = crate::http::process_http_packet(payload);

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
                .map(|url| regex.is_match(url))
                .unwrap_or(false);

            if content_match || url_match {
                // Create a formatted hex representation for logging
                let content_hex = content
                    .as_bytes()
                    .iter()
                    .map(|b| format!("{b:02X}"))
                    .collect::<Vec<String>>()
                    .join(" ");

                // Use different log formats for different match types
                let (match_type, fmt_msg, url) = match (content_match, url_match) {
                    (true, true) => (
                        "both",
                        "🚫 BLOCKED: matched raw & normalized",
                        normalized_url.as_deref().unwrap_or(""),
                    ),
                    (false, true) => (
                        "normalized",
                        "🚫 BLOCKED: matched normalized URL",
                        normalized_url.as_deref().unwrap_or(""),
                    ),
                    (true, false) => ("raw", "🚫 BLOCKED: matched raw content", ""),
                    _ => unreachable!(),
                };

                error!(
                    id = state.count,
                    src = %src_addr,
                    sport = src_port,
                    dport = dst_port,
                    rule = %regex.as_str(),
                    match_type,
                    normalized_url = %url,
                    "{fmt_msg}"
                );

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
