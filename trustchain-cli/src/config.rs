//! Core configuration types and utilities.
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::fs;
use toml;
use trustchain_core::TRUSTCHAIN_CONFIG;
use trustchain_ion::Endpoint;

lazy_static! {
    /// Lazy static reference to cli configuration loaded from `trustchain_config.toml`.
    pub static ref CLI_CONFIG: CLIConfig = parse_toml(
        &fs::read_to_string(std::env::var(TRUSTCHAIN_CONFIG).unwrap().as_str())
        .expect("Error reading trustchain_config.toml"));
}

/// Parses and returns cli configuration.
fn parse_toml(toml_str: &str) -> CLIConfig {
    toml::from_str::<Config>(toml_str)
        .expect("Error parsing trustchain_config.toml")
        .cli
}

/// Gets `trustchain-core` configuration variables.
pub fn cli_config() -> &'static CLI_CONFIG {
    &CLI_CONFIG
}

/// Configuration variables for `trustchain-cli` crate.
#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct CLIConfig {
    /// Root event unix time for first Trustchain root on testnet.
    pub root_event_time: u32,
    pub ion_endpoint: Endpoint,
}

/// Wrapper struct for parsing the `cli` table.
#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct Config {
    /// CLI configuration data.
    cli: CLIConfig,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize() {
        let config_string = r#"
        [cli]
        root_event_time = 1666971942
        ion_endpoint.host = "http://127.0.0.1"
        ion_endpoint.port = 3000

        [non_core]
        key = "value"
        "#;

        let config: CLIConfig = parse_toml(config_string);

        assert_eq!(
            config,
            CLIConfig {
                root_event_time: 1666971942,
                ion_endpoint: Endpoint::new("http://127.0.0.1".to_string(), 3000)
            }
        );
    }
}
