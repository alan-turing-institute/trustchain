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

pub fn get_config() -> &'static TRUSTCHAIN_CONFIG {
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
    pub env: String,
    pub root_event_time: u32,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct IonConfig {
    pub mongo_connection_string: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    // fn test_deserialize_simulation_config_empty() {
    fn test_deserialize() {
        let config_string = "
            [core]
            env = \"TRUSTCHAIN_DATA\"
            root_event_time = 42

            [ion]
            mongo_connection_string = \"mongodb://localhost:27017/\"
        ";

        let config: TrustchainConfig = toml::from_str(config_string).unwrap();

        assert_eq!(
            config,
            TrustchainConfig {
                core: CoreConfig {
                    env: "TRUSTCHAIN_DATA".to_string(),
                    root_event_time: 42_u32
                },
                ion: IonConfig {
                    mongo_connection_string: "mongodb://localhost:27017/".to_string()
                }
            }
        );
    }
}
