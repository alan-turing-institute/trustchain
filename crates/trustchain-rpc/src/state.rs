//! Trustchain RPC shared state.
use did_ion::sidetree::HTTPSidetreeDIDResolver;
use ssi::did_resolve::DIDResolver;
use trustchain_ion::ion::IONTest as ION;

use crate::config::RPCConfig;
use trustchain_ion::trustchain_resolver;
use trustchain_ion::verifier::TrustchainVerifier;

/// A shared app state for the RPC interface providing configuration, verifier, credential offer store,
/// presentation request store and root candidates cache for handlers.
pub struct AppState<T = HTTPSidetreeDIDResolver<ION>>
where
    T: DIDResolver + Send + Sync,
{
    pub config: RPCConfig,
    pub verifier: TrustchainVerifier<T>,
    // TODO:
    // pub credentials: HashMap<String, CredentialStoreItem>,
    // pub root_candidates: RwLock<HashMap<NaiveDate, RootCandidatesResult>>,
    // pub presentation_requests: HashMap<String, PresentationRequest>,
}

impl AppState {
    pub fn new(config: RPCConfig) -> Self {
        let verifier = TrustchainVerifier::new(trustchain_resolver(&config.ion_endpoint()));
        // TODO:
        // let path = std::env::var(TRUSTCHAIN_DATA).expect("TRUSTCHAIN_DATA env not set.");
        // let credentials: HashMap<String, CredentialStoreItem> = serde_json::from_reader(
        //     // let credentials: HashMap<String, Credential> = serde_json::from_reader(
        //     std::fs::read(std::path::Path::new(&path).join("credentials/offers/cache.json"))
        //         // If no cache, default to empty
        //         .unwrap_or_default()
        //         .as_slice(),
        // )
        // .unwrap_or_default();
        // let root_candidates = RwLock::new(HashMap::new());
        // let presentation_requests: HashMap<String, PresentationRequest> = serde_json::from_reader(
        //     std::fs::read(std::path::Path::new(&path).join("presentations/requests/cache.json"))
        //         // If no cache, default to empty
        //         .unwrap_or_default()
        //         .as_slice(),
        // )
        // .unwrap_or_default();
        Self {
            config,
            verifier,
            // credentials,
            // root_candidates,
            // presentation_requests,
        }
    }

    // pub fn new_with_cache(
    //     config: RPCConfig,
    //     credentials: HashMap<String, CredentialStoreItem>,
    //     presentation_requests: HashMap<String, PresentationRequest>,
    // ) -> Self {
    //     let verifier = TrustchainVerifier::new(trustchain_resolver(DEFAULT_VERIFIER_ENDPOINT));
    //     let root_candidates = RwLock::new(HashMap::new());
    //     Self {
    //         config,
    //         verifier,
    //         credentials,
    //         root_candidates,
    //         presentation_requests,
    //     }
    // }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RPCConfig;

    #[test]
    #[ignore = "requires TRUSTCHAIN_DATA and TRUSTCHAIN_CONFIG environment variables"]
    fn test_create_app_state() {
        AppState::new(RPCConfig::default());
        // AppState::new_with_cache(RPCConfig::default(), HashMap::new(), HashMap::new());
    }
}
