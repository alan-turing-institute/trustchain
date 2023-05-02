use crate::config::ServerConfig;
use tokio::sync::RwLock;
use trustchain_core::resolver::Resolver;
use trustchain_ion::{get_ion_resolver, verifier::IONVerifier, IONResolver};

const DEFAULT_VERIFIER_ENDPOINT: &str = "http://localhost:3000/";

pub struct AppState {
    pub config: ServerConfig,
    pub verifier: RwLock<IONVerifier<IONResolver>>,
}

impl AppState {
    pub fn new(config: ServerConfig) -> Self {
        let verifier = IONVerifier::new(Resolver::new(get_ion_resolver(DEFAULT_VERIFIER_ENDPOINT)));
        Self {
            config,
            verifier: RwLock::new(verifier),
        }
    }
}
