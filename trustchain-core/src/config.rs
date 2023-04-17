use crate::TRUSTCHAIN_DATA;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};
use toml;

lazy_static! {
    /// Lazy static reference to core configuration loaded from `trustchain_config.toml`.
    pub static ref CORE_CONFIG: CoreConfig = parse_toml(
        &fs::read_to_string(Path::new(std::env::var(TRUSTCHAIN_DATA).unwrap().as_str())
                                .join("trustchain_config.toml"))
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
    /// Root event unix time for first Trustchain root on testnet.
    pub root_event_time: u32,
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
        root_event_time = 1666971942

        [non_core]
        key = "value"
        "##;

        let config: CoreConfig = parse_toml(config_string);

        assert_eq!(
            config,
            CoreConfig {
                root_event_time: 1666971942,
            }
        );
    }
}
