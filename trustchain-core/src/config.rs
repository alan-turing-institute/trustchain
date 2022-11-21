// use std::collections::HashMap;
use std::default::Default;
use std::fs;
use toml;

use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};

lazy_static! {
    pub static ref TRUSTCHAIN_CONFIG: TrustchainCoreConfig = fs::read("trustchain_config.toml")
        .ok()
        .and_then(|data| toml::from_slice(&data).ok())
        .unwrap_or_default();
}

pub fn get_config() -> &'static TRUSTCHAIN_CONFIG {
    &TRUSTCHAIN_CONFIG
}

/// Core configuration settings
#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct CoreConfig {
    pub env: String,
    pub root_event_time: u32,
}

/// trustchain-core configuration settings
#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct TrustchainCoreConfig {
    pub core: CoreConfig,
}

impl Default for TrustchainCoreConfig {
    fn default() -> Self {
        TrustchainCoreConfig {
            core: CoreConfig {
                env: "TRUSTCHAIN_DATA".to_string(),
                root_event_time: 42,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    // fn test_deserialize_simulation_config_empty() {
    fn test_deserialize_core() {
        let config_string = br#"
            [core]
            env = "TRUSTCHAIN_DATA"
            root_event_time = 42
        "#;

        let config: TrustchainCoreConfig = toml::from_slice(config_string).unwrap();

        assert_eq!(config, TrustchainCoreConfig::default());

        let config_string = br#"
            [core]
            env = "TRUSTCHAIN_DATA"
            root_event_time = 43
        "#;

        let config: TrustchainCoreConfig = toml::from_slice(config_string).unwrap();

        assert_ne!(config, TrustchainCoreConfig::default());
    }
    #[test]
    fn test_deserialize_default() {
        let config_string = br#"
            [core]
        "#;

        let config: TrustchainCoreConfig = toml::from_slice(config_string).unwrap_or_default();

        assert_eq!(config, TrustchainCoreConfig::default())
    }
}
