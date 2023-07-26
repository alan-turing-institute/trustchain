//! Core configuration types and utilities.
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::fs;
use toml;
use trustchain_core::TRUSTCHAIN_CONFIG;

lazy_static! {
    /// Lazy static reference to core configuration loaded from `trustchain_config.toml`.
    pub static ref CLI_CONFIG: CLIConfig = parse_toml(
        &fs::read_to_string(std::env::var(TRUSTCHAIN_CONFIG).unwrap().as_str())
        .expect("Error reading trustchain_config.toml"));
}

/// Parses and returns core configuration.
fn parse_toml(toml_str: &str) -> CLIConfig {
    toml::from_str::<Config>(toml_str)
        .expect("Error parsing trustchain_config.toml")
        .core
}

/// Gets `trustchain-core` configuration variables.
pub fn cli_config() -> &'static CLI_CONFIG {
    &CLI_CONFIG
}

/// Configuration variables for `trustchain-core` crate.
#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct CLIConfig {
    /// Root event unix time for first Trustchain root on testnet.
    pub root_event_time: u32,
}

/// Wrapper struct for parsing the `core` table.
#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct Config {
    /// Core configuration data.
    core: CLIConfig,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize() {
        let config_string = r##"
        [core]
        root_event_time = 1666971942

        [non_core]
        key = "value"
        "##;

        let config: CLIConfig = parse_toml(config_string);

        assert_eq!(
            config,
            CLIConfig {
                root_event_time: 1666971942,
            }
        );
    }
}
