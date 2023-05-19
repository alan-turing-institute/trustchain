use crate::errors::TrustchainHTTPError;
use crate::state::AppState;
use async_trait::async_trait;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse};
use axum::Json;
use log::{debug, info, log};
use serde::{Deserialize, Serialize};
use ssi::did_resolve::DIDResolver;
use ssi::{
    did::Document,
    did_resolve::{DocumentMetadata, ResolutionResult},
};
use std::sync::Arc;
use trustchain_core::resolver::Resolver;
use trustchain_core::verifier::{Timestamp, Verifier};
use trustchain_core::{
    chain::{Chain, DIDChain},
    config::core_config,
};
use trustchain_ion::verifier::{IONVerifier, VerificationBundle};

// TODO: Potentially add IntoResponse impl for DIDChainResolutionResult to simplify return

#[async_trait]
pub trait TrustchainHTTP {
    /// Resolves a DID document.
    async fn resolve_did<T: DIDResolver + Send + Sync>(
        did: &str,
        resolver: &Resolver<T>,
    ) -> Result<ResolutionResult, TrustchainHTTPError>;

    /// Resolves a DID chain.
    async fn resolve_chain<T: DIDResolver + Send + Sync>(
        did: &str,
        verifier: &IONVerifier<T>,
        root_event_time: Timestamp,
    ) -> Result<DIDChainResolutionResult, TrustchainHTTPError>;

    // TODO: should we include a separate method to return verification bundle?
    async fn resolve_bundle<T: DIDResolver + Send + Sync>(
        did: &str,
        verifier: &IONVerifier<T>,
    ) -> Result<VerificationBundle, TrustchainHTTPError>;
}

pub struct TrustchainHTTPHandler {}

#[async_trait]
impl TrustchainHTTP for TrustchainHTTPHandler {
    async fn resolve_did<T: DIDResolver + Send + Sync>(
        did: &str,
        resolver: &Resolver<T>,
    ) -> Result<ResolutionResult, TrustchainHTTPError> {
        debug!("Resolving...");
        let result = resolver.resolve_as_result(did).await?;

        debug!("Resolved result: {:?}", result);
        match result {
            (_, Some(doc), Some(doc_meta)) => Ok(Self::to_resolution_result(doc, doc_meta)),
            // TODO: convert to (unknown) resolver error
            _ => Err(TrustchainHTTPError::InternalError),
        }
    }

    async fn resolve_chain<T: DIDResolver + Send + Sync>(
        did: &str,
        verifier: &IONVerifier<T>,
        root_event_time: Timestamp,
    ) -> Result<DIDChainResolutionResult, TrustchainHTTPError> {
        debug!("Verifying...");
        let chain = verifier.verify(did, root_event_time).await?;
        debug!("Verified did...");
        Ok(DIDChainResolutionResult::new(&chain))
    }

    async fn resolve_bundle<T: DIDResolver + Send + Sync>(
        did: &str,
        verifier: &IONVerifier<T>,
    ) -> Result<VerificationBundle, TrustchainHTTPError> {
        let bundle = verifier.verification_bundle(did).await?;
        Ok((*bundle).clone())
    }
}

#[derive(Deserialize, Debug)]
/// Struct for deserializing `root_event_time` from handler's query param.
pub struct RootEventTime {
    root_event_time: Timestamp,
}

impl TrustchainHTTPHandler {
    /// Handles get request for DID resolve API.
    pub async fn get_did_resolution(
        Path(did): Path<String>,
        State(app_state): State<Arc<AppState>>,
    ) -> impl IntoResponse {
        debug!("Received DID to resolve: {}", did.as_str());
        TrustchainHTTPHandler::resolve_did(did.as_str(), app_state.verifier.resolver())
            .await
            .map(|resolved_json| (StatusCode::OK, Json(resolved_json)))
    }

    /// Handles get request for DID chain resolution.
    pub async fn get_chain_resolution(
        Path(did): Path<String>,
        Query(root_event_time): Query<RootEventTime>,
        State(app_state): State<Arc<AppState>>,
    ) -> impl IntoResponse {
        debug!("Received DID to get trustchain: {}", did.as_str());
        // let mut verifier = .write().await;
        TrustchainHTTPHandler::resolve_chain(
            &did,
            &app_state.verifier,
            root_event_time.root_event_time,
        )
        .await
        .map(|chain| (StatusCode::OK, Json(chain)))
    }

    pub async fn get_verification_bundle(
        Path(did): Path<String>,
        State(app_state): State<Arc<AppState>>,
    ) -> impl IntoResponse {
        debug!("Received DID to get verification bundle: {}", did.as_str());
        TrustchainHTTPHandler::resolve_bundle(&did, &app_state.verifier)
            .await
            .map(|bundle| (StatusCode::OK, Json(bundle)))
    }

    pub fn to_resolution_result(doc: Document, doc_meta: DocumentMetadata) -> ResolutionResult {
        ResolutionResult {
            context: Some(serde_json::Value::String(
                "https://w3id.org/did-resolution/v1".to_string(),
            )),
            did_document: Some(doc),
            did_resolution_metadata: None,
            did_document_metadata: Some(doc_meta),
            property_set: None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DIDChainResolutionResult {
    did_chain: Vec<ResolutionResult>,
}

impl DIDChainResolutionResult {
    pub fn new(did_chain: &DIDChain) -> Self {
        Self {
            did_chain: did_chain
                .to_vec()
                .into_iter()
                .map(|(doc, doc_meta)| TrustchainHTTPHandler::to_resolution_result(doc, doc_meta))
                .collect::<Vec<_>>(),
        }
    }
}

#[cfg(test)]
mod tests {
    use trustchain_core::utils::canonicalize;
    use trustchain_ion::get_ion_resolver;

    use crate::{config::ServerConfig, data::TEST_ROOT_PLUS_2_RESOLVED};

    use super::*;

    const EXPECTED: &str = r##"{"did_doc":{"@context":["https://www.w3.org/ns/did/v1",{"@base":"did:ion:test:EiBcLZcELCKKtmun_CUImSlb2wcxK5eM8YXSq3MrqNe5wA"}],"id":"did:ion:test:EiBcLZcELCKKtmun_CUImSlb2wcxK5eM8YXSq3MrqNe5wA","controller":"did:ion:test:EiBwr2eTfupemVBq28VyIb8po0r_jpuHMUMFzw25Flnmrg","verificationMethod":[{"id":"#7Pwwl_Zs2Kc-s_Jk8zllHdmh3x6tFQWTpN5N5Zi4Rxk","type":"JsonWebSignature2020","controller":"did:ion:test:EiBcLZcELCKKtmun_CUImSlb2wcxK5eM8YXSq3MrqNe5wA","publicKeyJwk":{"kty":"EC","crv":"secp256k1","x":"tRK_sBPuLcho7blxIx9BriP8gEZcnRVhYJrhobEaIVM","y":"geBvTDCNhnzzP7nV6nRdifufHjXgnL2ajLSP50IK5Yk"}}],"authentication":["#7Pwwl_Zs2Kc-s_Jk8zllHdmh3x6tFQWTpN5N5Zi4Rxk"],"assertionMethod":["#7Pwwl_Zs2Kc-s_Jk8zllHdmh3x6tFQWTpN5N5Zi4Rxk"],"keyAgreement":["#7Pwwl_Zs2Kc-s_Jk8zllHdmh3x6tFQWTpN5N5Zi4Rxk"],"capabilityInvocation":["#7Pwwl_Zs2Kc-s_Jk8zllHdmh3x6tFQWTpN5N5Zi4Rxk"],"capabilityDelegation":["#7Pwwl_Zs2Kc-s_Jk8zllHdmh3x6tFQWTpN5N5Zi4Rxk"],"service":[{"id":"#TrustchainID","type":"Identity","serviceEndpoint":"https://www.turing.ac.uk"}]},"did_doc_meta":{"method":{"recoveryCommitment":"EiCSLo1DA2RJYQtSuoQJr4gSnA7H_c5xt13TMpFstrKfKg","updateCommitment":"EiBIzw7paqf0yBmt71YmlD68oAoAT2Luqoe6mHFC2MZGaw","published":true},"canonicalId":"did:ion:test:EiBcLZcELCKKtmun_CUImSlb2wcxK5eM8YXSq3MrqNe5wA","proof":{"proofValue":"eyJhbGciOiJFUzI1NksifQ.IkVpQk9YNWJoT3d0LS1OY2puSi1NdHhJb3oxeXNsd0ZPVFVvTXRkU0lJVzZnTlEi._FoemmrmrT99JbeaVyD0SZQYWJYFB_Lz8wY91mSIbPUWXgtXZ07ZLl-GXj1D9UhdZUuxbAGtTv4UR0MlAHawPA","type":"JsonWebSignature2020","id":"did:ion:test:EiBwr2eTfupemVBq28VyIb8po0r_jpuHMUMFzw25Flnmrg"}},"chunk_file":[31,139,8,0,0,0,0,0,0,3,221,152,201,146,163,72,18,134,223,69,231,162,26,16,32,84,55,54,137,85,2,196,62,86,134,33,118,177,67,176,136,182,122,247,33,171,178,171,231,214,105,214,154,75,222,194,28,15,247,136,63,62,243,112,226,207,93,20,151,32,24,118,223,254,243,231,174,13,64,152,197,191,198,65,8,242,166,222,125,219,245,113,91,6,97,188,251,178,139,154,112,172,226,26,236,190,109,174,227,189,204,67,41,126,254,242,206,163,205,51,31,250,179,118,12,101,193,226,175,252,137,236,234,252,201,170,153,103,12,46,109,38,61,119,225,73,207,133,154,25,20,108,177,69,3,207,54,222,38,137,67,83,219,241,253,150,167,117,0,198,62,70,97,20,222,190,254,142,47,206,197,91,190,176,159,54,231,33,14,91,20,39,10,100,243,40,192,115,179,112,204,54,92,182,1,123,69,69,77,178,123,119,201,168,35,56,121,118,247,192,53,81,43,177,121,213,99,109,88,9,202,202,238,193,8,120,242,45,249,219,212,71,132,195,216,209,139,214,254,128,205,6,199,206,84,152,181,198,186,212,161,77,59,144,163,112,142,113,18,250,4,214,151,98,247,227,109,69,125,219,12,63,213,217,5,195,16,247,111,250,40,49,200,154,104,11,184,69,206,54,105,242,48,248,41,219,182,188,248,73,165,125,28,255,20,236,203,46,12,218,224,158,151,57,120,10,245,212,252,246,250,219,204,198,101,156,254,50,127,255,241,253,203,182,213,126,202,195,248,127,228,53,250,113,216,206,39,200,107,129,253,91,63,33,122,75,187,105,241,123,10,87,71,109,147,191,29,211,46,3,160,29,190,253,241,199,60,207,95,199,176,252,26,132,95,199,109,51,223,127,188,101,24,219,40,0,49,211,84,85,14,126,29,235,142,203,233,203,4,162,11,198,58,119,189,87,113,184,132,40,36,77,152,216,150,243,170,95,178,133,90,132,153,232,82,66,134,5,135,218,84,249,215,204,76,70,43,161,205,62,67,195,200,131,58,89,191,99,119,145,240,112,124,223,193,116,127,239,41,71,127,148,139,112,139,138,182,121,61,51,22,109,199,126,164,218,154,222,177,73,75,242,13,220,142,153,103,237,111,157,102,156,113,91,166,44,182,59,38,244,193,187,185,239,204,224,123,8,209,74,125,191,30,125,152,134,216,251,1,183,19,92,201,219,233,74,183,145,21,92,229,240,60,74,158,210,157,84,243,51,48,19,37,241,215,180,153,254,17,26,142,225,48,3,21,171,146,24,7,75,13,209,22,110,115,225,18,53,14,113,43,184,171,52,42,204,74,63,5,178,189,66,218,43,160,129,47,33,242,128,59,98,223,202,79,148,205,205,224,232,30,14,78,63,78,237,149,81,59,85,50,47,199,129,62,192,201,168,165,175,135,38,148,39,168,143,220,75,49,167,118,90,42,246,19,61,175,218,73,63,43,50,30,119,133,159,233,254,17,172,98,218,233,77,250,14,141,36,150,24,168,6,129,165,238,237,100,94,107,218,9,73,64,151,71,211,130,80,245,148,3,207,86,43,197,63,17,8,173,125,6,104,194,160,250,64,161,97,92,164,229,208,73,57,201,15,72,139,137,220,33,89,241,224,23,73,161,56,160,82,69,204,57,173,11,69,5,200,169,166,95,194,12,75,196,250,109,74,136,94,72,178,74,237,52,182,104,152,154,181,106,101,165,246,101,103,170,103,8,181,22,129,170,224,7,249,122,102,236,69,31,131,194,210,164,68,82,135,3,44,207,147,87,79,61,98,102,153,21,161,154,10,70,76,77,184,16,111,6,95,121,103,6,43,239,48,139,95,117,179,30,56,211,191,102,200,210,34,71,102,45,129,193,242,7,129,182,90,148,134,61,206,68,58,109,248,12,204,52,203,7,144,97,201,24,195,89,59,189,94,250,34,116,89,157,22,158,250,242,104,141,54,37,154,148,150,93,164,40,89,95,65,203,189,130,206,175,64,70,108,84,81,117,132,10,80,164,172,168,6,147,89,85,117,53,37,102,65,71,221,214,253,91,53,107,14,167,40,129,116,53,95,143,140,174,216,18,159,251,212,128,2,219,123,112,199,203,147,204,170,48,82,220,21,87,125,137,97,202,174,59,113,124,16,176,162,240,142,76,108,116,165,62,237,49,103,95,84,168,54,223,247,222,42,24,215,70,64,146,229,22,137,171,98,89,80,106,185,107,68,150,216,103,64,38,202,134,240,35,151,19,53,192,211,20,80,205,124,234,250,90,37,88,56,124,184,172,234,151,71,84,58,15,225,120,94,122,139,150,143,57,232,145,250,37,212,20,248,202,210,32,60,119,46,72,137,128,20,108,184,166,117,163,167,91,44,25,70,20,97,26,105,168,111,144,170,46,246,255,161,163,169,152,40,149,44,152,103,117,158,236,247,68,30,227,152,135,33,12,185,4,48,78,43,39,167,166,173,197,71,134,138,223,246,250,222,5,55,78,68,243,173,114,244,31,7,147,184,165,153,229,67,98,76,107,1,69,164,56,225,37,233,19,73,72,207,38,6,54,252,12,212,196,209,71,154,224,173,182,176,143,174,125,222,235,155,86,27,52,31,1,136,202,35,205,64,8,63,204,234,148,20,11,59,116,79,23,234,17,165,175,64,230,4,164,11,164,20,20,109,85,215,4,49,177,104,213,163,253,205,11,139,96,8,22,219,24,19,123,225,23,148,186,2,41,124,61,50,152,115,49,70,56,132,24,202,88,208,187,25,99,148,47,174,122,101,17,134,146,222,97,82,82,155,40,88,183,91,81,41,254,42,52,112,196,218,80,12,112,87,168,5,7,19,70,10,118,251,214,224,220,156,186,203,15,214,159,30,170,4,3,19,210,10,121,254,12,200,124,160,198,48,226,144,66,202,138,66,222,72,163,74,132,171,227,40,6,104,221,83,244,179,11,121,126,186,5,23,216,118,28,224,81,243,75,154,153,120,46,136,132,55,247,119,182,118,160,85,241,232,64,197,171,124,160,178,232,56,206,98,138,212,48,2,11,20,183,192,178,240,122,96,214,158,187,101,103,84,130,167,246,136,14,92,105,105,152,115,64,158,7,213,12,12,150,142,206,28,43,49,83,151,136,93,59,188,3,163,103,215,41,78,41,247,212,30,42,23,114,181,91,39,68,183,170,198,97,144,61,8,242,212,29,194,118,208,172,200,180,242,79,81,99,230,160,159,243,176,248,72,19,108,185,2,104,236,32,186,42,167,220,106,160,81,126,96,68,7,243,69,5,123,23,221,84,103,227,76,160,211,85,157,78,224,37,133,230,160,206,115,233,123,3,42,133,208,224,139,5,185,150,37,31,85,217,126,33,192,73,179,141,246,130,95,112,47,199,222,158,60,94,206,13,208,37,127,160,213,81,14,179,230,112,223,254,234,151,35,221,231,42,153,114,94,88,235,86,230,138,125,214,220,185,64,176,254,106,130,211,152,158,12,150,185,100,245,186,170,135,218,34,106,61,202,147,49,225,31,78,90,203,104,240,144,111,42,14,11,18,238,126,138,23,154,77,220,188,78,63,210,8,183,116,170,67,135,149,215,46,203,241,174,165,236,236,55,166,234,33,148,166,219,20,210,123,71,123,148,244,128,6,130,114,155,223,2,253,23,168,13,248,12,229,19,0,0],"provisional_index_file":[31,139,8,0,0,0,0,0,0,3,171,86,74,206,40,205,203,46,86,178,138,174,134,48,221,50,115,82,67,139,50,149,172,148,2,115,131,205,203,125,221,179,194,194,205,51,2,141,131,67,11,2,43,93,44,242,11,195,204,35,220,82,74,11,34,211,163,76,195,45,67,195,221,146,2,220,61,252,34,188,149,106,99,107,1,54,210,97,134,78,0,0,0],"core_index_file":[31,139,8,0,0,0,0,0,0,3,141,212,199,174,163,88,16,6,224,119,241,186,45,17,13,238,29,209,68,3,198,216,152,209,8,17,14,57,28,115,136,190,186,239,62,183,103,223,150,215,37,85,125,250,171,84,95,59,56,244,115,137,202,190,139,26,181,75,193,42,151,13,240,134,114,247,123,231,180,174,159,76,180,217,234,62,1,196,86,191,21,154,79,121,103,126,125,160,35,44,93,54,125,178,163,182,49,45,161,43,48,219,118,191,118,61,4,67,52,254,180,66,187,223,95,187,100,0,209,8,118,191,255,249,218,161,41,203,202,85,140,198,232,79,33,5,205,24,41,17,42,126,102,72,165,40,90,17,145,49,188,134,1,49,37,84,35,81,75,185,234,26,110,77,10,107,95,32,178,215,112,79,233,142,45,125,59,56,63,51,6,144,244,51,24,54,161,111,219,114,108,65,55,254,223,69,128,192,177,9,235,34,25,113,203,225,180,254,202,242,68,99,219,246,186,221,20,215,122,158,116,105,166,93,193,208,110,106,188,236,190,191,127,189,55,241,210,164,8,14,119,201,42,30,71,39,32,228,234,138,192,86,228,90,78,101,89,13,42,78,150,168,72,12,13,130,29,151,191,155,248,188,74,17,227,242,156,205,114,78,29,47,134,84,174,16,228,34,199,118,168,73,29,165,21,59,47,54,205,126,62,204,220,7,38,153,12,28,200,9,100,125,170,75,187,48,221,88,199,74,170,240,100,171,244,105,89,204,155,163,166,202,34,17,203,41,145,255,221,36,30,33,32,103,160,14,251,218,83,111,247,243,117,43,87,175,122,38,11,173,223,164,69,77,243,205,160,188,192,30,209,33,207,63,48,213,166,8,231,110,104,18,39,92,140,179,166,217,65,159,47,13,124,20,212,109,24,117,102,143,91,231,215,169,24,9,223,124,183,187,50,100,20,226,25,206,252,113,240,143,94,176,88,215,62,19,112,94,209,91,119,185,133,214,1,103,236,40,14,201,192,106,63,200,73,132,235,75,227,125,104,162,229,129,213,52,194,18,234,145,91,198,57,176,47,68,90,236,37,11,75,194,121,205,56,59,175,185,55,57,217,44,78,151,192,184,50,198,65,149,61,78,122,134,138,137,202,76,76,26,225,1,146,65,171,49,61,195,140,240,69,143,206,7,57,37,218,237,25,187,98,72,202,117,197,250,194,229,94,80,162,112,161,36,63,39,15,167,33,203,172,59,211,211,78,107,154,193,59,211,75,114,171,229,134,14,44,128,143,140,204,30,212,193,165,247,131,85,145,22,118,49,101,10,207,241,148,115,125,134,155,156,79,238,201,59,166,235,1,63,46,14,110,47,5,84,229,23,105,235,233,186,214,94,87,139,88,166,209,160,100,220,241,37,15,130,255,198,196,251,168,218,104,162,185,107,116,1,220,115,140,157,67,82,164,105,242,180,80,194,75,209,247,152,146,206,49,107,143,64,208,63,200,73,84,125,199,123,176,157,84,5,177,64,25,231,120,182,73,253,128,34,182,188,79,201,243,5,66,129,197,213,159,29,44,112,122,99,18,152,107,30,116,19,47,181,248,162,93,131,233,152,169,102,128,32,220,8,228,10,88,54,41,16,85,172,201,193,128,24,63,184,113,33,95,130,154,92,82,94,193,171,116,11,65,252,216,212,35,233,81,38,104,12,0,171,83,123,159,57,206,180,238,3,63,191,249,5,130,107,244,184,200,17,23,237,225,140,238,212,59,218,64,229,110,199,49,74,152,208,235,136,147,87,19,202,104,28,244,76,255,99,250,247,251,251,63,31,235,88,97,154,5,0,0],"transaction":[2,0,0,0,1,84,44,124,47,248,26,227,17,193,51,188,118,43,47,150,172,109,133,18,110,203,39,228,40,227,179,20,239,17,50,202,109,1,0,0,0,106,71,48,68,2,32,68,112,141,98,90,162,58,148,59,236,204,74,133,175,88,117,116,203,96,216,49,242,138,0,203,17,82,75,101,114,139,105,2,32,120,19,65,199,163,39,23,249,188,171,58,231,118,19,173,237,162,20,245,194,67,47,41,27,200,156,238,219,232,169,249,249,1,33,3,210,138,101,166,212,146,135,234,245,80,56,11,62,159,113,207,113,16,105,102,75,44,32,130,109,119,241,154,12,3,85,7,255,255,255,255,2,0,0,0,0,0,0,0,0,54,106,52,105,111,110,58,57,46,81,109,88,83,112,120,56,114,76,65,77,74,99,68,109,55,68,76,103,107,111,82,114,99,120,115,76,89,70,52,53,78,50,83,118,65,115,88,86,70,113,88,82,98,74,99,34,54,238,0,0,0,0,0,25,118,169,20,199,246,99,10,196,245,226,169,38,84,22,59,206,40,9,49,99,20,24,221,136,172,0,0,0,0],"merkle_block":[0,0,109,36,85,214,38,82,119,39,229,196,210,125,23,11,15,162,147,219,220,194,210,170,13,210,21,30,13,0,0,0,0,0,0,0,161,230,104,20,226,198,172,72,66,148,60,195,14,204,85,202,69,97,109,53,254,85,180,111,22,125,74,16,153,79,185,8,38,249,91,99,192,255,63,25,103,198,130,155,62,0,0,0,7,87,238,227,212,231,26,115,145,3,194,151,159,172,63,88,232,140,25,138,219,32,215,174,171,235,88,15,132,205,243,194,221,19,40,114,111,169,88,225,24,11,73,29,27,106,238,182,63,144,67,27,237,57,236,41,107,127,129,222,204,8,57,80,80,107,253,220,36,94,240,215,73,228,47,203,154,13,76,244,62,152,70,26,172,118,244,64,219,32,109,237,212,48,46,190,43,226,237,19,36,130,138,112,93,196,186,9,203,154,121,87,232,180,123,190,180,149,60,81,53,46,38,47,137,3,107,45,87,6,230,101,213,165,50,49,88,122,73,190,76,107,187,79,19,253,67,53,65,142,83,165,145,120,191,239,248,151,38,50,162,161,147,252,164,223,169,192,220,124,81,193,63,94,220,205,223,238,81,65,84,203,37,87,126,246,210,88,244,1,78,161,31,252,209,156,111,180,197,171,37,45,185,183,182,77,207,252,108,96,112,111,70,75,35,247,19,149,25,48,199,91,188,42,207,2,219,1],"block_header":[0,0,109,36,85,214,38,82,119,39,229,196,210,125,23,11,15,162,147,219,220,194,210,170,13,210,21,30,13,0,0,0,0,0,0,0,161,230,104,20,226,198,172,72,66,148,60,195,14,204,85,202,69,97,109,53,254,85,180,111,22,125,74,16,153,79,185,8,38,249,91,99,192,255,63,25,103,198,130,155]}"##;

    #[tokio::test]
    // Test of the bundle endpoint by using the verifier `fetch_bundle()` method to get from the endpoint
    async fn test_fetch_bundle() {
        // let verifier = IONVerifier::new(get_ion_resolver("http://localhost:3000"));
        // let did = "did:ion:test:EiBcLZcELCKKtmun_CUImSlb2wcxK5eM8YXSq3MrqNe5wA";

        // let result = verifier.fetch_bundle(did, Some("http://127.0.0.1:8081/did/bundle".to_string())).await;
        let result = serde_json::from_str::<VerificationBundle>(EXPECTED);
        println!("{:?}", result);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_get_did_resolver() {
        let shared_state = Arc::new(AppState::new(ServerConfig::default()));
        let response = TrustchainHTTPHandler::get_did_resolution(
            Path("did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q".to_string()),
            State(shared_state),
        )
        .await
        .into_response();
        let status = response.status();
        assert_eq!(status, StatusCode::OK);
        let body = serde_json::from_str::<ResolutionResult>(
            &String::from_utf8(
                hyper::body::to_bytes(response.into_body())
                    .await
                    .unwrap()
                    .to_vec(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(canonicalize(&body).unwrap(), TEST_ROOT_PLUS_2_RESOLVED)
    }
}
