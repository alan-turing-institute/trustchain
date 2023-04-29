use crate::{config::ServerConfig, HTTPVerifier};
use std::net::IpAddr;
use tokio::sync::Mutex;
use trustchain_ion::get_ion_resolver;

const DEFAULT_VERIFIER_ENDPOINT: &str = "http://localhost:3000/";

pub struct AppState {
    pub host_reference: IpAddr,
    pub port: u16,
    pub verifier: Mutex<HTTPVerifier>,
}

impl AppState {
    pub fn new(config: &ServerConfig) -> Self {
        Self {
            host_reference: config.host_reference,
            port: config.port,
            verifier: Mutex::new(HTTPVerifier::new(get_ion_resolver(
                DEFAULT_VERIFIER_ENDPOINT,
            ))),
        }
    }
}
