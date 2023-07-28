use crate::config::HTTPConfig;
use ssi::vc::Credential;
use std::collections::HashMap;
use trustchain_core::{resolver::Resolver, TRUSTCHAIN_DATA};
use trustchain_ion::{get_ion_resolver, verifier::IONVerifier, IONResolver};

const DEFAULT_VERIFIER_ENDPOINT: &str = "http://localhost:3000/";

/// A shared app state for handlers.
pub struct AppState {
    pub config: HTTPConfig,
    pub verifier: IONVerifier<IONResolver>,
    pub credentials: HashMap<String, Credential>,
}

impl AppState {
    pub fn new(config: HTTPConfig) -> Self {
        let verifier = IONVerifier::new(Resolver::new(get_ion_resolver(DEFAULT_VERIFIER_ENDPOINT)));
        let path = std::env::var(TRUSTCHAIN_DATA).expect("TRUSTCHAIN_DATA env not set.");
        let credentials: HashMap<String, Credential> = serde_json::from_reader(
            std::fs::read(std::path::Path::new(&path).join("credentials/offers/cache.json"))
                .expect("Credential cache does not exist.")
                .as_slice(),
        )
        .expect("Credential cache could not be deserialized.");
        Self {
            config,
            verifier,
            credentials,
        }
    }
    pub fn new_with_cache(config: HTTPConfig, credentials: HashMap<String, Credential>) -> Self {
        let verifier = IONVerifier::new(Resolver::new(get_ion_resolver(DEFAULT_VERIFIER_ENDPOINT)));
        Self {
            config,
            verifier,
            credentials,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::HTTPConfig;

    #[test]
    #[ignore = "requires TRUSTCHAIN_DATA and TRUSTCHAIN_CONFIG environment variables"]
    fn test_create_app_state() {
        AppState::new(HTTPConfig::default());
        AppState::new_with_cache(HTTPConfig::default(), HashMap::new());
    }
}
