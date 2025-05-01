use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// Configuration structure matching the wireveil.toml format
#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    pub services: HashMap<String, ServiceConfig>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ServiceConfig {
    pub port: u16,
    pub block: Vec<String>,
}
