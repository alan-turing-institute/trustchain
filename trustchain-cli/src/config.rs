//! Core configuration types and utilities.
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::fs;
use toml;
use trustchain_core::TRUSTCHAIN_CONFIG;
use trustchain_ion::{config::IONConfig, Endpoint};

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
    pub ion_config: IONConfig,
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

        [cli.ion_config]
        mongo_connection_string = "mongodb://localhost:27017/"
        mongo_database_ion_core = "ion-testnet-core"

        bitcoin_connection_string = "http://localhost:18332"
        bitcoin_rpc_username = "admin"
        bitcoin_rpc_password = "bitcoin_rpc_password"

        [non_cli]
        key = "value"
        "#;

        let config: CLIConfig = parse_toml(config_string);

        assert_eq!(
            config,
            CLIConfig {
                root_event_time: 1666971942,
                ion_endpoint: Endpoint::new("http://127.0.0.1".to_string(), 3000),
                ion_config: IONConfig {
                    mongo_connection_string: "mongodb://localhost:27017/".to_string(),
                    mongo_database_ion_core: "ion-testnet-core".to_string(),
                    bitcoin_connection_string: "http://localhost:18332".to_string(),
                    bitcoin_rpc_username: "admin".to_string(),
                    bitcoin_rpc_password: "bitcoin_rpc_password".to_string()
                }
            }
        );
    }
}
