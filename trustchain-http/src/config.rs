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
const DEFAULT_PORT: u16 = 8081;

/// HTTP configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HTTPConfig {
    /// Hostname for server
    pub host: IpAddr,
    /// Hostname reference. For example, Android emulator 10.0.2.2 refers to 127.0.0.1 of machine running emulator.
    pub host_display: String,
    /// Port for server
    pub port: u16,
    /// Optional issuer DID
    pub issuer_did: Option<String>,
    /// Flag indicating whether server uses https
    pub https: bool,
    /// Path containing certificate and key necessary for https
    pub https_path: Option<String>,
    /// Root event time for verifier.
    pub root_event_time: Option<Timestamp>,
}

impl std::fmt::Display for HTTPConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{:?}", self)
    }
}

impl Default for HTTPConfig {
    fn default() -> Self {
        Self {
            host: IpAddr::from_str(DEFAULT_HOST).unwrap(),
            host_display: DEFAULT_HOST.to_string(),
            port: DEFAULT_PORT,
            issuer_did: None,
            https: false,
            https_path: None,
            root_event_time: None,
        }
    }
}

impl HTTPConfig {
    /// Provides formatted string of server config address.
    pub fn to_address(&self) -> String {
        format!("{}:{}", self.host, self.port).parse().unwrap()
    }
    /// Provides `SocketAdd` of server config address.
    pub fn to_socket_address(&self) -> SocketAddr {
        format!("{}:{}", self.host, self.port)
            .parse::<SocketAddr>()
            .unwrap()
    }
}

lazy_static! {
    /// Lazy static reference to core configuration loaded from `trustchain_config.toml`.
    pub static ref HTTP_CONFIG: HTTPConfig = parse_toml(
        &fs::read_to_string(std::env::var(TRUSTCHAIN_CONFIG).unwrap().as_str())
        .expect("Error reading trustchain_config.toml"));
}

/// Parses and returns core configuration.
fn parse_toml(toml_str: &str) -> HTTPConfig {
    toml::from_str::<Config>(toml_str)
        .expect("Error parsing trustchain_config.toml")
        .http
}

/// Gets `trustchain-http` configuration variables.
pub fn http_config() -> &'static HTTP_CONFIG {
    &HTTP_CONFIG
}

/// Wrapper struct for parsing the `http` config table.
#[derive(Serialize, Deserialize, Debug, Clone)]
struct Config {
    /// HTTP configuration data.
    http: HTTPConfig,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize() {
        let config_string = r#"
        [http]
        host = "127.0.0.1"
        host_display = "127.0.0.1"
        port = 8081
        issuer_did = "did:ion:test:EiBcLZcELCKKtmun_CUImSlb2wcxK5eM8YXSq3MrqNe5wA"
        https = false

        [non_http]
        key = "value"
        "#;

        let config: HTTPConfig = parse_toml(config_string);

        assert_eq!(
            config,
            HTTPConfig {
                issuer_did: Some(
                    "did:ion:test:EiBcLZcELCKKtmun_CUImSlb2wcxK5eM8YXSq3MrqNe5wA".to_string()
                ),
                ..HTTPConfig::default()
            }
        );
    }
}
