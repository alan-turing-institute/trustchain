//! Trustchain RPC configuration types and utilities.
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::fs;
use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
};
use toml;
use trustchain_core::verifier::Timestamp;
use trustchain_core::TRUSTCHAIN_CONFIG;

const DEFAULT_HOST: &str = "127.0.0.1";
const DEFAULT_PORT: u16 = 4444;

/// RPC configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RPCConfig {
    /// Host address for RPC server.
    pub host: Option<IpAddr>,
    /// Port for RPC server.
    pub port: Option<u16>,
    // /// Path containing certificate and key necessary for https.
    // pub https_path: Option<String>,
    /// Root event time for verifier.
    pub root_event_time: Option<Timestamp>,
}

impl std::fmt::Display for RPCConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{:?}", self)
    }
}

impl Default for RPCConfig {
    fn default() -> Self {
        Self {
            host: Some(IpAddr::from_str(DEFAULT_HOST).unwrap()),
            port: Some(DEFAULT_PORT),
            // https_path: None,
            root_event_time: None,
        }
    }
}

impl RPCConfig {
    /// Provides formatted string of server config address.
    pub fn to_address(&self) -> String {
        format!(
            "{}:{}",
            self.host.expect("Default it not configured"),
            self.port.expect("Default it not configured")
        )
        .parse()
        .unwrap()
    }

    /// Provides `SocketAdd` of server config address.
    pub fn to_socket_address(&self) -> SocketAddr {
        self.to_address().parse::<SocketAddr>().unwrap()
    }

    fn fill_from(self, other: Self) -> Self {
        Self {
            host: self.host.or(other.host),
            port: self.port.or(other.port),
            root_event_time: self.root_event_time.or(other.root_event_time),
        }
    }
}

lazy_static! {
    /// Lazy static reference to core configuration loaded from `trustchain_config.toml`.
    pub static ref RPC_CONFIG: RPCConfig = parse_toml(
        &fs::read_to_string(std::env::var(TRUSTCHAIN_CONFIG).unwrap().as_str())
        .expect("Error reading trustchain_config.toml"));
}

/// Parses and returns RPC configuration.
fn parse_toml(toml_str: &str) -> RPCConfig {
    let config = toml::from_str::<Config>(toml_str).expect("Error parsing trustchain_config.toml");
    // Replace any None values in the config with defaults.
    config.rpc.fill_from(RPCConfig::default())
}

/// Gets `trustchain-rpc` configuration variables.
pub fn rpc_config() -> &'static RPC_CONFIG {
    &RPC_CONFIG
}

/// Wrapper struct for parsing the `rpc` config table.
#[derive(Serialize, Deserialize, Debug, Clone)]
struct Config {
    /// RPC configuration data.
    rpc: RPCConfig,
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_deserialize() {
        let config_string = r#"
        [rpc]
        host = "127.0.0.1"
        port = 4444

        [non_rpc]
        key = "value"
        "#;

        let config: RPCConfig = parse_toml(&config_string);
        assert_eq!(config, RPCConfig::default());
    }
}
