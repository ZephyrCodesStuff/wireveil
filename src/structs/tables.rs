#![allow(dead_code, reason = "They're still useful")]

use std::fmt::{self, Display};
use std::io;
use std::process::{Command, Output};
use std::str::FromStr;
use thiserror::Error;
use tracing::{debug, error};

#[derive(Debug, Error)]
pub enum IPTablesError {
    #[error("I/O error: {0}")]
    IoError(#[from] io::Error),

    #[error("Command error ({0}): {1}")]
    CommandError(i32, String),

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("Invalid chain: {0}")]
    InvalidChain(String),

    #[error("Chain does not exist: {0}")]
    NoSuchChain(String),

    #[error("Failed to parse command output: {0}")]
    OutputParseError(String),
}

#[derive(Debug, Clone, Copy)]
pub enum Table {
    Filter,
    Mangle,
    Nat,
    Raw,
    Security,
}

impl Display for Table {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Table::Filter => write!(f, "filter"),
            Table::Mangle => write!(f, "mangle"),
            Table::Nat => write!(f, "nat"),
            Table::Raw => write!(f, "raw"),
            Table::Security => write!(f, "security"),
        }
    }
}

#[derive(Debug, Clone)]
pub enum Chain {
    Builtin(BuiltinChain),
    Custom(String),
}

impl Display for Chain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Chain::Builtin(chain) => write!(f, "{}", chain),
            Chain::Custom(name) => write!(f, "{}", name),
        }
    }
}

impl FromStr for Chain {
    type Err = IPTablesError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(chain) = BuiltinChain::from_str(s) {
            Ok(Chain::Builtin(chain))
        } else {
            Ok(Chain::Custom(s.to_string()))
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum BuiltinChain {
    INPUT,
    OUTPUT,
    FORWARD,
    PREROUTING,
    POSTROUTING,
}

impl Display for BuiltinChain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BuiltinChain::INPUT => write!(f, "INPUT"),
            BuiltinChain::OUTPUT => write!(f, "OUTPUT"),
            BuiltinChain::FORWARD => write!(f, "FORWARD"),
            BuiltinChain::PREROUTING => write!(f, "PREROUTING"),
            BuiltinChain::POSTROUTING => write!(f, "POSTROUTING"),
        }
    }
}

impl FromStr for BuiltinChain {
    type Err = IPTablesError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "INPUT" => Ok(BuiltinChain::INPUT),
            "OUTPUT" => Ok(BuiltinChain::OUTPUT),
            "FORWARD" => Ok(BuiltinChain::FORWARD),
            "PREROUTING" => Ok(BuiltinChain::PREROUTING),
            "POSTROUTING" => Ok(BuiltinChain::POSTROUTING),
            _ => Err(IPTablesError::InvalidChain(s.to_string())),
        }
    }
}

#[derive(Debug, Clone)]
pub enum Target {
    Accept,
    Drop,
    Reject,
    Queue(u16),
    Return,
    Jump(Chain),
    Goto(Chain),
}

impl Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Target::Accept => write!(f, "ACCEPT"),
            Target::Drop => write!(f, "DROP"),
            Target::Reject => write!(f, "REJECT"),
            Target::Queue(num) => write!(f, "NFQUEUE --queue-num {}", num),
            Target::Return => write!(f, "RETURN"),
            Target::Jump(chain) => write!(f, "JUMP {}", chain),
            Target::Goto(chain) => write!(f, "GOTO {}", chain),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Rule {
    protocol: Option<Protocol>,
    source: Option<String>,
    destination: Option<String>,
    sport: Option<u16>,
    dport: Option<u16>,
    in_interface: Option<String>,
    out_interface: Option<String>,
    target: Target,
}

impl Rule {
    pub fn new(target: Target) -> Self {
        Rule {
            protocol: None,
            source: None,
            destination: None,
            sport: None,
            dport: None,
            in_interface: None,
            out_interface: None,
            target,
        }
    }

    pub fn protocol(mut self, protocol: Protocol) -> Self {
        self.protocol = Some(protocol);
        self
    }

    pub fn source(mut self, source: &str) -> Self {
        self.source = Some(source.to_string());
        self
    }

    pub fn destination(mut self, destination: &str) -> Self {
        self.destination = Some(destination.to_string());
        self
    }

    pub fn sport(mut self, port: u16) -> Self {
        self.sport = Some(port);
        self
    }

    pub fn dport(mut self, port: u16) -> Self {
        self.dport = Some(port);
        self
    }

    pub fn in_interface(mut self, interface: &str) -> Self {
        self.in_interface = Some(interface.to_string());
        self
    }

    pub fn out_interface(mut self, interface: &str) -> Self {
        self.out_interface = Some(interface.to_string());
        self
    }

    pub fn to_args(&self) -> Vec<String> {
        let mut args = Vec::new();

        if let Some(protocol) = &self.protocol {
            args.push("-p".to_string());
            args.push(protocol.to_string());
        }

        if let Some(source) = &self.source {
            args.push("-s".to_string());
            args.push(source.clone());
        }

        if let Some(destination) = &self.destination {
            args.push("-d".to_string());
            args.push(destination.clone());
        }

        if let Some(sport) = self.sport {
            args.push("--sport".to_string());
            args.push(sport.to_string());
        }

        if let Some(dport) = self.dport {
            args.push("--dport".to_string());
            args.push(dport.to_string());
        }

        if let Some(in_interface) = &self.in_interface {
            args.push("-i".to_string());
            args.push(in_interface.clone());
        }

        if let Some(out_interface) = &self.out_interface {
            args.push("-o".to_string());
            args.push(out_interface.clone());
        }

        match &self.target {
            Target::Queue(num) => {
                args.push("-j".to_string());
                args.push("NFQUEUE".to_string());
                args.push("--queue-num".to_string());
                args.push(num.to_string());
            }
            Target::Jump(chain) => {
                args.push("-j".to_string());
                args.push(chain.to_string());
            }
            Target::Goto(chain) => {
                args.push("-g".to_string());
                args.push(chain.to_string());
            }
            _ => {
                args.push("-j".to_string());
                args.push(self.target.to_string());
            }
        }

        args
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Protocol {
    TCP,
    UDP,
    ICMP,
    All,
}

impl Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Protocol::TCP => write!(f, "tcp"),
            Protocol::UDP => write!(f, "udp"),
            Protocol::ICMP => write!(f, "icmp"),
            Protocol::All => write!(f, "all"),
        }
    }
}

pub struct IPTables {
    ipv6: bool,
}

impl IPTables {
    pub fn new() -> Self {
        IPTables { ipv6: false }
    }

    pub fn new_ipv6() -> Self {
        IPTables { ipv6: true }
    }

    fn command(&self) -> Command {
        if self.ipv6 {
            Command::new("ip6tables")
        } else {
            Command::new("iptables")
        }
    }

    fn run_command(&self, args: &[&str]) -> Result<Output, IPTablesError> {
        debug!("Running iptables command: iptables {}", args.join(" "));

        let output = self.command().args(args).output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            let exit_code = output.status.code().unwrap_or(-1);

            // Don't log as errors for specific iptables exit codes/messages that are often expected
            if exit_code == 1 && stderr.contains("No chain/target/match by that name") {
                debug!("iptables: {}", stderr.trim());
            } else {
                error!("iptables command failed: {}", stderr);
            }

            return Err(IPTablesError::CommandError(exit_code, stderr));
        }

        Ok(output)
    }

    // Generic command runner with common error handling
    fn execute_command(
        &self,
        command: &str,
        table: Table,
        chain: impl Into<Chain>,
        args: Vec<&str>,
    ) -> Result<(), IPTablesError> {
        let chain = chain.into();
        let chain_str = format!("{}", chain);
        let table_str = table.to_string();
        let mut cmd_args = vec!["-t", &table_str, command, &chain_str];
        cmd_args.extend(args);

        match self.run_command(&cmd_args) {
            Ok(_) => Ok(()),

            // For certain commands like deletion (-D) or flushing (-F),
            // if the chain doesn't exist, it's not an error we should propagate
            Err(IPTablesError::CommandError(_, stderr))
                if (command == "-D" || command == "-F" || command == "-X")
                    && stderr.contains("No chain/target/match by that name") =>
            {
                debug!(
                    "Chain '{}' doesn't exist, but that's ok for {} command",
                    chain_str, command
                );
                Ok(())
            }

            // For -N, "Chain already exists" is not an error
            Err(IPTablesError::CommandError(_, stderr))
                if command == "-N" && stderr.contains("Chain already exists") =>
            {
                debug!(
                    "Chain '{}' already exists, but that's ok for new chain command",
                    chain_str
                );
                Ok(())
            }

            // All other errors are propagated
            Err(e) => Err(e),
        }
    }

    pub fn append(
        &self,
        table: Table,
        chain: impl Into<Chain>,
        rule: &Rule,
    ) -> Result<(), IPTablesError> {
        let args = rule.to_args();
        let rule_args: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        self.execute_command("-A", table, chain, rule_args)
    }

    pub fn append_rule_str(
        &self,
        table: Table,
        chain: impl Into<Chain>,
        rule_str: &str,
    ) -> Result<(), IPTablesError> {
        let rule_parts: Vec<&str> = rule_str.split_whitespace().collect();
        self.execute_command("-A", table, chain, rule_parts)
    }

    pub fn delete(
        &self,
        table: Table,
        chain: impl Into<Chain>,
        rule: &Rule,
    ) -> Result<(), IPTablesError> {
        let args = rule.to_args();
        let rule_args: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        self.execute_command("-D", table, chain, rule_args)
    }

    pub fn delete_rule_str(
        &self,
        table: Table,
        chain: impl Into<Chain>,
        rule_str: &str,
    ) -> Result<(), IPTablesError> {
        let rule_parts: Vec<&str> = rule_str.split_whitespace().collect();
        self.execute_command("-D", table, chain.into(), rule_parts)
    }

    pub fn new_chain(&self, table: Table, chain: impl Into<Chain>) -> Result<(), IPTablesError> {
        let chain = chain.into();
        // Check if the chain already exists first to avoid error messages in logs
        if self
            .list_chains(table)?
            .iter()
            .any(|c| c == &chain.to_string())
        {
            debug!("Chain '{}' already exists, skipping creation", chain);
            return Ok(());
        }

        self.execute_command("-N", table, chain, vec![])
    }

    pub fn flush_chain(&self, table: Table, chain: impl Into<Chain>) -> Result<(), IPTablesError> {
        self.execute_command("-F", table, chain.into(), vec![])
    }

    pub fn delete_chain(&self, table: Table, chain: impl Into<Chain>) -> Result<(), IPTablesError> {
        let chain = chain.into();
        self.execute_command("-X", table, chain, vec![])
    }

    pub fn list_chains(&self, table: Table) -> Result<Vec<String>, IPTablesError> {
        let table = table.to_string();
        let args = vec!["-t", &table, "-S"];

        let output = self.run_command(&args)?;
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();

        // Parse chains from iptables -S output
        let chains: Vec<String> = stdout
            .lines()
            .filter_map(|line| {
                if line.starts_with("-P ") {
                    // Built-in chain policies
                    Some(line.split_whitespace().nth(1)?.to_string())
                } else if line.starts_with("-N ") {
                    // Custom chains
                    Some(line.split_whitespace().nth(1)?.to_string())
                } else {
                    None
                }
            })
            .collect();

        Ok(chains)
    }

    pub fn check_rule(
        &self,
        table: Table,
        chain: impl Into<Chain>,
        rule: &Rule,
    ) -> Result<bool, IPTablesError> {
        let chain = chain.into();
        let chain_str = format!("{}", chain);
        let table_str = table.to_string();
        let mut args = vec!["-t", &table_str, "-C", &chain_str];

        let rule_args = rule.to_args();
        let rule_args: Vec<&str> = rule_args.iter().map(|s| s.as_str()).collect();

        args.extend(rule_args);

        match self.run_command(&args) {
            Ok(_) => Ok(true), // Rule exists

            // Expected behavior: rule or chain doesn't exist
            Err(IPTablesError::CommandError(1, stderr)) => {
                if stderr.contains("No chain/target/match by that name") {
                    debug!(
                        "Chain '{}' doesn't exist yet, so rule can't exist",
                        chain_str
                    );
                } else {
                    debug!("Rule doesn't exist in chain '{}'", chain_str);
                }
                Ok(false)
            }

            // Unexpected errors
            Err(e) => Err(e),
        }
    }

    // Methods for policy management
    pub fn set_policy(
        &self,
        table: Table,
        chain: BuiltinChain,
        target: Target,
    ) -> Result<(), IPTablesError> {
        let table_str = table.to_string();
        let chain_str = chain.to_string();
        let target_str = target.to_string();

        let args = vec!["-t", &table_str, "-P", &chain_str, &target_str];
        self.run_command(&args).map(|_| ())
    }

    // List all rules in a chain
    pub fn list_rules(
        &self,
        table: Table,
        chain: impl Into<Chain>,
    ) -> Result<Vec<String>, IPTablesError> {
        let chain_str = format!("{}", chain.into());
        let table_str = table.to_string();

        let args = vec!["-t", &table_str, "-S", &chain_str];

        let output = self.run_command(&args)?;
        let stdout = String::from_utf8_lossy(&output.stdout);

        Ok(stdout.lines().map(|s| s.to_string()).collect())
    }
}
