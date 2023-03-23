use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};
use toml;

lazy_static! {
    /// Lazy static reference to core configuration loaded from `trustchain_config.toml`.
    pub static ref CORE_CONFIG: CoreConfig = parse_toml(
        &fs::read_to_string(Path::new(env!("CARGO_WORKSPACE_DIR")).join("trustchain_config.toml"))
        .expect("Error reading trustchain_config.toml")
    );
}

/// Parses and returns core configuration.
fn parse_toml(toml_str: &str) -> CoreConfig {
    toml::from_str::<Config>(toml_str)
        .expect("Error parsing trustchain_config.toml")
        .core
}

/// Gets `trustchain-core` configuration variables.
pub fn core_config() -> &'static CORE_CONFIG {
    &CORE_CONFIG
}

/// Configuration variables for `trustchain-core` crate.
#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct CoreConfig {
    /// Environment variable name for Trustchain data.
    pub trustchain_data: String,
    /// Root event unix time for first Trustchain root on testnet.
    pub root_event_time: u32,
    /// Root event unix time for second Trustchain root on testnet.
    pub root_event_time_2378493: u32,
}

/// Wrapper struct for parsing the `core` table.
#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct Config {
    /// Core configuration data.
    core: CoreConfig,
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

        [non_core]
        key = "value"
        "##;

        let config: CoreConfig = parse_toml(config_string);

        assert_eq!(
            config,
            CoreConfig {
                trustchain_data: "TRUSTCHAIN_DATA".to_string(),
                root_event_time: 1666265405,
                root_event_time_2378493: 1666971942
            }
        );
    }
}
