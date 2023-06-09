//! ION node configuration types and utilities.
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::fs;
use toml;
use trustchain_core::TRUSTCHAIN_CONFIG;

lazy_static! {
    /// Lazy static reference to ION configuration loaded from `trustchain_config.toml`.
    pub static ref ION_CONFIG: IONConfig = parse_toml(
        &fs::read_to_string(std::env::var(TRUSTCHAIN_CONFIG).unwrap().as_str())
        .expect("Error reading trustchain_config.toml"));
}

/// Parses and maps ION subfields to a new type.
fn parse_toml(toml_str: &str) -> IONConfig {
    toml::from_str::<Config>(toml_str)
        .expect("Error parsing trustchain_config.toml")
        .ion
}

/// Gets `trustchain-ion` configuration variables.
pub fn ion_config() -> &'static ION_CONFIG {
    &ION_CONFIG
}

/// Configuration variables for `trustchain-ion` crate.
#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct IONConfig {
    /// MongoDB endpoint.
    pub mongo_connection_string: String,
    /// MongoDB ION core database name.
    pub mongo_database_ion_core: String,
    /// Bitcoin Core endpoint (testnet port: 18332).
    pub bitcoin_connection_string: String,
    /// Bitcoin Core RPC username.
    pub bitcoin_rpc_username: String,
    /// Bitcoin Core RPC password.
    pub bitcoin_rpc_password: String,
}

/// Wrapper struct for parsing the `ion` table.
#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct Config {
    /// ION configuration data.
    ion: IONConfig,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize() {
        let config_string = r##"
        [non_ion]
        key = "value"

        [ion]
        mongo_connection_string = "mongodb://localhost:27017/"
        mongo_database_ion_core = "ion-testnet-core"

        bitcoin_connection_string = "http://localhost:18332"
        bitcoin_rpc_username = "admin"
        bitcoin_rpc_password = "bitcoin_rpc_password"
        "##;

        let config: IONConfig = parse_toml(config_string);

        assert_eq!(
            config,
            IONConfig {
                mongo_connection_string: "mongodb://localhost:27017/".to_string(),
                mongo_database_ion_core: "ion-testnet-core".to_string(),
                bitcoin_connection_string: "http://localhost:18332".to_string(),
                bitcoin_rpc_username: "admin".to_string(),
                bitcoin_rpc_password: "bitcoin_rpc_password".to_string(),
            }
        );
    }
}
