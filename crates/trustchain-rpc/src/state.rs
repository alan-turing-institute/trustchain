//! Trustchain RPC shared state.
use chrono::NaiveDate;
use did_ion::sidetree::HTTPSidetreeDIDResolver;
use ssi::did_resolve::DIDResolver;
use std::collections::HashMap;
use std::sync::RwLock;
use trustchain_ion::ion::IONTest as ION;
use trustchain_ion::root::RootCandidatesResult;

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
    pub root_candidates: RwLock<HashMap<NaiveDate, RootCandidatesResult>>,
}

impl AppState {
    pub fn new(config: RPCConfig) -> Self {
        let verifier = TrustchainVerifier::new(trustchain_resolver(&config.ion_endpoint()));
        let root_candidates = RwLock::new(HashMap::new());
        Self {
            config,
            verifier,
            root_candidates,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RPCConfig;

    #[test]
    fn test_create_app_state() {
        AppState::new(RPCConfig::default());
    }
}
