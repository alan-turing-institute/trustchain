use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::fs;
use toml;

// parse just core config fields from .toml into the core config struct

lazy_static! {
    pub static ref CORE_CONFIG: CoreConfigFields = parse_toml(
        &fs::read_to_string(concat!(
            env!("CARGO_WORKSPACE_DIR"),
            "/trustchain_config.toml"
        ))
        .expect("Error reading trustchain_config.toml")
    );
}

// parse and map core subfields to a new type
fn parse_toml(toml_str: &str) -> CoreConfigFields {
    let core: CoreConfig = toml::from_str(toml_str).expect("Error parsing trustchain_config.toml");
    core.core
}

pub fn core_config() -> &'static CORE_CONFIG {
    &CORE_CONFIG
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct CoreConfigFields {
    /// Rust variable for Trustchain data environment variable.
    pub trustchain_data: String,
    /// Root event unix time for first Trustchain root on testnet.
    pub root_event_time: u32,
    /// Root event unix time for second Trustchain root on testnet.
    pub root_event_time_2378493: u32,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct CoreConfig {
    pub core: CoreConfigFields,
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

        let config: CoreConfigFields = parse_toml(config_string);

        assert_eq!(
            config,
            CoreConfigFields {
                trustchain_data: "TRUSTCHAIN_DATA".to_string(),
                root_event_time: 1666265405,
                root_event_time_2378493: 1666971942
            }
        );
    }
}
