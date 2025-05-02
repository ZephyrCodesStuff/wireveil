use std::collections::HashMap;

use regex::Regex;
use tracing::error;

use super::config::Config;

pub struct State {
    pub count: u32,
    pub service_rules: HashMap<u16, Vec<Regex>>,
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
