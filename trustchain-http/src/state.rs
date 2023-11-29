use crate::root::RootCandidatesResult;
use crate::{config::HTTPConfig, verifier::PresentationRequest};
use chrono::NaiveDate;
use did_ion::sidetree::HTTPSidetreeDIDResolver;
use ssi::did_resolve::DIDResolver;
use ssi::vc::Credential;
use std::collections::HashMap;
use std::sync::RwLock;
use trustchain_core::TRUSTCHAIN_DATA;
use trustchain_ion::ion::IONTest as ION;
use trustchain_ion::trustchain_resolver;
use trustchain_ion::verifier::TrustchainVerifier;

const DEFAULT_VERIFIER_ENDPOINT: &str = "http://localhost:3000/";

/// A shared app state for handlers.
pub struct AppState<T = HTTPSidetreeDIDResolver<ION>>
where
    T: DIDResolver + Send + Sync,
{
    pub config: HTTPConfig,
    pub verifier: TrustchainVerifier<T>,
    pub credentials: HashMap<String, Credential>,
    pub root_candidates: RwLock<HashMap<NaiveDate, RootCandidatesResult>>,
    pub presentation_requests: HashMap<String, PresentationRequest>,
}

impl AppState {
    pub fn new(config: HTTPConfig) -> Self {
        let verifier = TrustchainVerifier::new(trustchain_resolver(DEFAULT_VERIFIER_ENDPOINT));
        let path = std::env::var(TRUSTCHAIN_DATA).expect("TRUSTCHAIN_DATA env not set.");
        let credentials: HashMap<String, Credential> = serde_json::from_reader(
            std::fs::read(std::path::Path::new(&path).join("credentials/offers/cache.json"))
                // If no cache, default to empty
                .unwrap_or_default()
                .as_slice(),
        )
        // .expect("Credential cache could not be deserialized.");
        .unwrap_or_default();
        let root_candidates = RwLock::new(HashMap::new());
        let presentation_requests: HashMap<String, PresentationRequest> = serde_json::from_reader(
            std::fs::read(std::path::Path::new(&path).join("presentations/requests/cache.json"))
                // If no cache, default to empty
                .unwrap_or_default()
                .as_slice(),
        )
        // .expect("Presentation cache could not be deserialized.");
        .unwrap_or_default();
        Self {
            config,
            verifier,
            credentials,
            root_candidates,
            presentation_requests,
        }
    }
    pub fn new_with_cache(
        config: HTTPConfig,
        credentials: HashMap<String, Credential>,
        presentation_requests: HashMap<String, PresentationRequest>,
    ) -> Self {
        let verifier = TrustchainVerifier::new(trustchain_resolver(DEFAULT_VERIFIER_ENDPOINT));
        let root_candidates = RwLock::new(HashMap::new());
        Self {
            config,
            verifier,
            credentials,
            root_candidates,
            presentation_requests,
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
        AppState::new_with_cache(HTTPConfig::default(), HashMap::new(), HashMap::new());
    }
}
