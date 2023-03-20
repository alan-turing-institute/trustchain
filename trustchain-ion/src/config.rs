use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::fs;
use toml;

// parse just core config fields from .toml into the core config struct

lazy_static! {
    pub static ref ION_CONFIG: IONConfigFields = parse_toml(
        &fs::read_to_string(concat!(
            env!("CARGO_WORKSPACE_DIR"),
            "/trustchain_config.toml"
        ))
        .expect("Error reading trustchain_config.toml")
    );
}

// parse and map core subfields to a new type
fn parse_toml(toml_str: &str) -> IONConfigFields {
    let ion: IONConfig = toml::from_str(toml_str).expect("Error parsing trustchain_config.toml");
    ion.ion
}

pub fn ion_config() -> &'static ION_CONFIG {
    &ION_CONFIG
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct IONConfigFields {
    // MongoDB
    pub mongo_connection_string: String,
    pub mongo_database_ion_testnet_core: String,

    // Bitcoin (TESTNET PORT: 18332!)
    pub bitcoin_connection_string: String,
    pub bitcoin_rpc_username: String,
    pub bitcoin_rpc_password: String,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct IONConfig {
    pub ion: IONConfigFields,
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

        let config: IONConfigFields = parse_toml(config_string);

        assert_eq!(
            config,
            IONConfigFields {
                mongo_connection_string: "mongodb://localhost:27017/".to_string(),
                mongo_database_ion_testnet_core: "ion-testnet-core".to_string(),
                bitcoin_connection_string: "http://localhost:18332".to_string(),
                bitcoin_rpc_username: "admin".to_string(),
                bitcoin_rpc_password: "lWrkJlpj8SbnNRUJfO6qwIFEWkD+I9kL4REsFyMBlow=".to_string(),
            }
        );
    }
}
