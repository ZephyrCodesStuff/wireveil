use anyhow::Result;
use tracing::{info, warn};

use crate::{
    CHAIN_NAME, QUEUE_IDX,
    structs::{
        config::Config,
        tables::{self, BuiltinChain, Chain, IPTables, IPTablesError, Rule, Table, Target},
    },
};

pub fn setup(config: &Config) -> Result<()> {
    let ipt: IPTables = IPTables::new();

    // Create a new chain for our rules
    info!("Creating iptables chain '{}'...", CHAIN_NAME);
    let chain = Chain::Custom(CHAIN_NAME.to_string());

    match ipt.new_chain(Table::Filter, chain.clone()) {
        Ok(_) => {}
        Err(IPTablesError::CommandError(_, stderr)) if stderr.contains("Chain already exists") => {
            info!("Chain '{}' already exists, continuing...", CHAIN_NAME);
        }
        Err(e) => {
            return Err(anyhow::anyhow!(
                "Failed to create iptables chain '{}': {}",
                CHAIN_NAME,
                e
            ));
        }
    }

    // Add our jump rule to the INPUT chain if it doesn't already exist
    let rule = Rule::new(Target::Jump(chain.clone()));

    // Check if the jump rule exists
    let rule_exists =
        match ipt.check_rule(Table::Filter, Chain::Builtin(BuiltinChain::INPUT), &rule) {
            Ok(exists) => exists,
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "Failed to check if jump rule exists: {}",
                    e
                ));
            }
        };

    if !rule_exists {
        info!("Adding jump rule from INPUT chain to {}...", CHAIN_NAME);
        match ipt.append(Table::Filter, Chain::Builtin(BuiltinChain::INPUT), &rule) {
            Ok(_) => {}
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "Failed to add jump rule to INPUT chain: {}",
                    e
                ));
            }
        }
    } else {
        info!("Jump rule from INPUT to {} already exists", CHAIN_NAME);
    }

    // Configure rules for each service
    for (service_name, service) in &config.services {
        info!(
            service = service_name,
            port = service.port,
            "Setting up iptables for service"
        );

        // Forward traffic to NFQUEUE
        let rule = Rule::new(Target::Queue(QUEUE_IDX))
            .protocol(tables::Protocol::TCP)
            .dport(service.port);

        // Check if rule already exists before adding
        let rule_exists = match ipt.check_rule(Table::Filter, chain.clone(), &rule) {
            Ok(exists) => exists,
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "Failed to check if service rule exists: {}",
                    e
                ));
            }
        };

        if !rule_exists {
            info!(
                "Adding rule for service '{}' on port {}...",
                service_name, service.port
            );
            match ipt.append(Table::Filter, chain.clone(), &rule) {
                Ok(_) => {}
                Err(e) => {
                    return Err(anyhow::anyhow!(
                        "Failed to add iptables rule for service '{}': {}",
                        service_name,
                        e
                    ));
                }
            }
        } else {
            info!(
                "Rule for service '{}' on port {} already exists",
                service_name, service.port
            );
        }
    }

    Ok(())
}

pub fn cleanup() -> Result<()> {
    let ipt = IPTables::new();

    // Remove jump rule from INPUT chain
    let chain = Chain::Custom(CHAIN_NAME.to_string());
    let rule = Rule::new(Target::Jump(chain.clone()));

    // Try to delete the jump rule - ignore errors if it doesn't exist
    if let Err(e) = ipt.delete(Table::Filter, Chain::Builtin(BuiltinChain::INPUT), &rule) {
        // We can ignore certain errors during cleanup
        if !matches!(e, IPTablesError::CommandError(_, ref s) if s.contains("No chain/target/match by that name"))
        {
            warn!("Error removing jump rule: {}", e);
        }
    }

    // Flush the chain - ignore errors if it doesn't exist
    if let Err(e) = ipt.flush_chain(Table::Filter, chain.clone()) {
        if !matches!(e, IPTablesError::CommandError(_, ref s) if s.contains("No chain/target/match by that name"))
        {
            warn!("Error flushing chain: {}", e);
        }
    }

    // Delete the chain - ignore errors if it doesn't exist
    if let Err(e) = ipt.delete_chain(Table::Filter, chain) {
        if !matches!(e, IPTablesError::CommandError(_, ref s) if s.contains("No chain/target/match by that name"))
        {
            warn!("Error deleting chain: {}", e);
        }
    }

    Ok(())
}
