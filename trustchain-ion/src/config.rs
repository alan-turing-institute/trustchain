//! ION node configuration types and utilities.
use chrono::NaiveDate;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::{fs, str::FromStr};
use toml;
use trustchain_core::{root::RootConfig, TRUSTCHAIN_CONFIG};

lazy_static! {
    /// Lazy static reference to ION configuration loaded from `trustchain_config.toml`.
    pub static ref ION_CONFIG: IONConfig = parse_ion_toml(
        &fs::read_to_string(std::env::var(TRUSTCHAIN_CONFIG).unwrap().as_str())
        .expect("Error reading trustchain_config.toml"));
    pub static ref ROOT_CONFIG: Vec<RootConfig> = parse_root_toml(
        &fs::read_to_string(std::env::var(TRUSTCHAIN_CONFIG).unwrap().as_str())
        .expect("Error reading trustchain_config.toml"));
}

/// Parses and maps ION subfields to a new type.
fn parse_ion_toml(toml_str: &str) -> IONConfig {
    toml::from_str::<Config>(toml_str)
        .expect("Error parsing trustchain_config.toml")
        .ion
}

/// Gets `trustchain-ion` configuration variables.
pub fn ion_config() -> &'static ION_CONFIG {
    &ION_CONFIG
}

/// Parses and maps root subfields to a new type.
fn parse_root_toml(toml_str: &str) -> Vec<RootConfig> {
    let config = toml::from_str::<Config>(toml_str).expect("Error parsing trustchain_config.toml");
    let mut root_configs = Vec::<RootConfig>::new();
    if config.root.is_none() {
        return root_configs;
    }
    for root_config_params in config.root.unwrap() {
        let date = NaiveDate::from_str(&root_config_params.date).expect(&format!(
            "Error parsing root date from string: {}",
            &root_config_params.date
        ));
        let root_config = RootConfig::new(date, &root_config_params.confirmation_code)
            .expect("Error parsing root config parameters from trustchain_config.toml");
        root_configs.push(root_config);
    }
    root_configs
}

/// Gets `root` configuration variables.
pub fn root_config() -> &'static ROOT_CONFIG {
    &ROOT_CONFIG
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

/// Struct for parsing root config parameters from toml.
#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct RootTomlConfig {
    /// Root event date.
    pub date: String,
    /// Confirmation code.
    pub confirmation_code: String,
}

/// Wrapper struct for parsing the `ion` table and `root` tables.
#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct Config {
    /// ION configuration data.
    ion: IONConfig,
    /// Root configuration data.
    root: Option<Vec<RootTomlConfig>>,
}

#[cfg(test)]
mod tests {
    use chrono::NaiveDate;

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

        [[root]]
        date = "2022-10-20"
        confirmation_code = "1fa"

        [[root]]
        date = "2009-01-03"
        confirmation_code = "xyz"
        "##;

        let ion_config: IONConfig = parse_ion_toml(config_string);

        assert_eq!(
            ion_config,
            IONConfig {
                mongo_connection_string: "mongodb://localhost:27017/".to_string(),
                mongo_database_ion_core: "ion-testnet-core".to_string(),
                bitcoin_connection_string: "http://localhost:18332".to_string(),
                bitcoin_rpc_username: "admin".to_string(),
                bitcoin_rpc_password: "bitcoin_rpc_password".to_string(),
            }
        );

        let root_configs: Vec<RootConfig> = parse_root_toml(config_string);

        assert_eq!(root_configs.len(), 2);

        assert_eq!(
            root_configs[0],
            RootConfig::new(NaiveDate::from_ymd_opt(2022, 10, 20).unwrap(), "1fa").unwrap()
        );

        assert_eq!(
            root_configs[1],
            RootConfig::new(NaiveDate::from_ymd_opt(2009, 01, 03).unwrap(), "xyz").unwrap()
        );
    }

    #[test]
    fn test_deserialize_no_root() {
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

        let ion_config: IONConfig = parse_ion_toml(config_string);

        assert_eq!(
            ion_config,
            IONConfig {
                mongo_connection_string: "mongodb://localhost:27017/".to_string(),
                mongo_database_ion_core: "ion-testnet-core".to_string(),
                bitcoin_connection_string: "http://localhost:18332".to_string(),
                bitcoin_rpc_username: "admin".to_string(),
                bitcoin_rpc_password: "bitcoin_rpc_password".to_string(),
            }
        );

        let root_configs: Vec<RootConfig> = parse_root_toml(config_string);

        assert_eq!(root_configs.len(), 0);
    }
}
