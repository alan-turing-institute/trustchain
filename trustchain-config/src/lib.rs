use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::fs;
use toml;

lazy_static! {
    pub static ref TRUSTCHAIN_CONFIG: TrustchainConfig = toml::from_str(
        &fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/trustchain_config.toml"
        ))
        .expect("Error reading trustchain_config.toml")
    )
    .expect("Error parsing trustchain_config.toml");
}

pub fn config() -> &'static TRUSTCHAIN_CONFIG {
    &TRUSTCHAIN_CONFIG
}

/// trustchain-core configuration settings
#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct TrustchainConfig {
    pub core: CoreConfig,
    pub ion: IonConfig,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct CoreConfig {
    /// Rust variable for Trustchain data environment variable.
    pub trustchain_data: String,
    /// Root event unix time for first Trustchain root on testnet.
    pub root_event_time: u32,
    /// Root event unix time for second Trustchain root on testnet.
    pub root_event_time_2378493: u32,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct IonConfig {
    // MongoDB
    pub mongo_connection_string: String,
    pub mongo_database_ion_testnet_core: String,

    // Bitcoin (TESTNET PORT: 18332!)
    pub bitcoin_connection_string: String,
    pub bitcoin_rpc_username: String,
    pub bitcoin_rpc_password: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize() {
        let config_string = r##"
        [core]
        trustchain_data = "TRUSTCHAIN_DATA"
        root_event_time = 1666265405
        root_event_time_2378493 = 1666971942

        [ion]
        mongo_connection_string = "mongodb://localhost:27017/"
        mongo_database_ion_testnet_core = "ion-testnet-core"

        bitcoin_connection_string = "http://localhost:18332"
        bitcoin_rpc_username = "admin"
        bitcoin_rpc_password = "lWrkJlpj8SbnNRUJfO6qwIFEWkD+I9kL4REsFyMBlow="
        "##;

        let config: TrustchainConfig = toml::from_str(config_string).unwrap();

        assert_eq!(
            config,
            TrustchainConfig {
                core: CoreConfig {
                    trustchain_data: "TRUSTCHAIN_DATA".to_string(),
                    root_event_time: 1666265405,
                    root_event_time_2378493: 1666971942
                },
                ion: IonConfig {
                    mongo_connection_string: "mongodb://localhost:27017/".to_string(),
                    mongo_database_ion_testnet_core: "ion-testnet-core".to_string(),
                    bitcoin_connection_string: "http://localhost:18332".to_string(),
                    bitcoin_rpc_username: "admin".to_string(),
                    bitcoin_rpc_password: "lWrkJlpj8SbnNRUJfO6qwIFEWkD+I9kL4REsFyMBlow="
                        .to_string(),
                }
            }
        );
    }
}
