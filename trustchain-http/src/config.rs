use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::fs;
use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
};
use toml;
use trustchain_core::TRUSTCHAIN_CONFIG;

const DEFAULT_HOST: &str = "127.0.0.1";
const DEFAULT_PORT: u16 = 8081;

/// Server config.
#[derive(clap::Parser, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerConfig {
    /// Hostname for server
    #[clap(short = 's', long)]
    #[arg(default_value_t = IpAddr::from_str(DEFAULT_HOST).unwrap())]
    pub host: IpAddr,
    /// Hostname reference. For example, Android emulator 10.0.2.2 refers to 127.0.0.1 of machine running emulator.
    #[clap(short = 'r', long)]
    #[arg(default_value_t = IpAddr::from_str(DEFAULT_HOST).unwrap())]
    pub host_reference: IpAddr,
    /// Port for server
    #[clap(short = 'p', long)]
    #[arg(default_value_t = DEFAULT_PORT)]
    pub port: u16,
    /// Issuer did
    #[clap(short = 'd', long)]
    pub issuer_did: Option<String>,
}

impl std::fmt::Display for ServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Host: {} | Host reference: {} | Port: {}",
            self.host, self.host_reference, self.port
        )?;
        Ok(())
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: IpAddr::from_str(DEFAULT_HOST).unwrap(),
            host_reference: IpAddr::from_str(DEFAULT_HOST).unwrap(),
            port: DEFAULT_PORT,
            issuer_did: None,
        }
    }
}

impl ServerConfig {
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
    pub static ref HTTP_CONFIG: ServerConfig = parse_toml(
        &fs::read_to_string(std::env::var(TRUSTCHAIN_CONFIG).unwrap().as_str())
        .expect("Error reading trustchain_config.toml"));
}

/// Parses and returns core configuration.
fn parse_toml(toml_str: &str) -> ServerConfig {
    toml::from_str::<Config>(toml_str)
        .expect("Error parsing trustchain_config.toml")
        .http
}

/// Gets `trustchain-http` configuration variables.
pub fn http_config() -> &'static HTTP_CONFIG {
    &HTTP_CONFIG
}

/// Wrapper struct for parsing the `http` table.
#[derive(Serialize, Deserialize, Debug, Clone)]
struct Config {
    /// HTTP configuration data.
    http: ServerConfig,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize() {
        let config_string = r##"
        [http]
        host = "127.0.0.1"
        host_reference = "127.0.0.1"
        port = 8081
        issuer_did = "did:ion:test:EiBcLZcELCKKtmun_CUImSlb2wcxK5eM8YXSq3MrqNe5wA"

        [non_http]
        key = "value"
        "##;

        let config: ServerConfig = parse_toml(config_string);

        assert_eq!(
            config,
            ServerConfig {
                issuer_did: Some(
                    "did:ion:test:EiBcLZcELCKKtmun_CUImSlb2wcxK5eM8YXSq3MrqNe5wA".to_string()
                ),
                ..ServerConfig::default()
            }
        );
    }
}
