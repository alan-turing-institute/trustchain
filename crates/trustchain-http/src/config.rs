//! Trustchain HTTP configuration types and utilities.
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
    /// Hostname displayed in generated QR codes, e.g. for credential offers.
    /// If using a local server with an Android emulator for Trustchain Mobile development, the
    /// hostname `10.0.2.2` refers to `127.0.0.1` (localhost) of the machine running the emulator.
    pub host_display: String,
    /// Host address for server.
    pub host: IpAddr,
    /// Port for server.
    pub port: u16,
    /// ION host.
    pub ion_host: IpAddr,
    /// ION port.
    pub ion_port: u16,
    /// Optional server DID if attesting dDIDs or verifying credentials/presentations.
    pub server_did: Option<String>,
    /// Flag indicating whether server uses https.
    pub https: bool,
    /// Path containing certificate and key necessary for https.
    pub https_path: Option<String>,
    /// Display downstream DIDs (instead of URLs) in QR codes for verifiable endpoint retrieval
    /// (`None` by default and unwrapped as `true`).
    pub verifiable_endpoints: Option<bool>,
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
            ion_host: IpAddr::from_str(DEFAULT_HOST).unwrap(),
            ion_port: 3000,
            server_did: None,
            https: false,
            https_path: None,
            verifiable_endpoints: None,
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
    /// Provide "http" or "https" according to config.
    pub fn http_scheme(&self) -> &str {
        if self.https {
            "https"
        } else {
            "http"
        }
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
    use bitcoin::Network;
    use trustchain_ion::utils::BITCOIN_NETWORK;

    use super::*;

    #[test]
    fn test_deserialize() {
        let server_did = match BITCOIN_NETWORK
            .as_ref()
            .expect("Integration test requires Bitcoin")
        {
            Network::Testnet => "did:ion:test:EiBcLZcELCKKtmun_CUImSlb2wcxK5eM8YXSq3MrqNe5wA",
            Network::Testnet4 => "did:ion:test:EiA-CAfMgrNRa2Gv5D8ZF7AazX9nKxnSlYkYViuKeomymw",
            network @ _ => {
                panic!("No test fixtures for network: {:?}", network);
            }
        };

        let config_string = r#"
        [http]
        host = "127.0.0.1"
        host_display = "127.0.0.1"
        port = 8081
        ion_host = "127.0.0.1"
        ion_port = 3000
        server_did = "<SERVER_DID>"
        https = false

        [non_http]
        key = "value"
        "#
        .replace("<SERVER_DID>", server_did);

        let config: HTTPConfig = parse_toml(&config_string);
        assert!(config.verifiable_endpoints.is_none());
        assert_eq!(
            config,
            HTTPConfig {
                server_did: Some(server_did.to_string()),
                ..HTTPConfig::default()
            }
        );
    }
}
