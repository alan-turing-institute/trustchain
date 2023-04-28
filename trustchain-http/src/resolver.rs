use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse};
use axum::Json;
use base64::engine::Config;
use core::time;
use log::{debug, info, log, Level};
use serde::{Deserialize, Serialize};
use serde_json::{to_string, to_string_pretty};
use ssi::{
    did::Document,
    did_resolve::{DocumentMetadata, ResolutionResult},
};
use trustchain_core::data::{TEST_ROOT_PLUS_2_DOCUMENT, TEST_ROOT_PLUS_2_DOCUMENT_METADATA};
use trustchain_core::{
    chain::{Chain, DIDChain},
    config::core_config,
    utils::canonicalize,
};

use crate::data::TEST_ROOT_PLUS_2_RESOLVED;

use async_trait::async_trait;
use did_ion::{sidetree::SidetreeClient, ION};
use thiserror::Error;
use trustchain_core::verifier::Verifier;
use trustchain_ion::verifier::IONVerifier;
use trustchain_ion::{get_ion_resolver, IONResolver};

// TODO: Move to utils, add doc comment
trait EmptyResponse {
    fn empty_response() -> Self;
}

impl EmptyResponse for ResolutionResult {
    fn empty_response() -> Self {
        Self {
            context: None,
            ..Default::default()
        }
    }
}

// TODO: refine error variants and move to seperate module
#[derive(Error, Debug)]
pub enum TrustchainHTTPError {
    #[error("Some internal error.")]
    InternalError,
}

#[async_trait]
pub trait TrustchainHTTP {
    /// Resolves a DID chain, will this include the bundle?
    async fn resolve_chain(did: &str) -> DIDChainResolutionResult;

    /// Resolves a DID chain, will this include the bundle?
    async fn resolve_did(did: &str) -> Result<ResolutionResult, TrustchainHTTPError>;

    // TODO: should we include a separate method to return verification bundle?
    fn resolve_bundle(did: &str);
}

pub struct TrustchainHTTPHandler {}

#[async_trait]
impl TrustchainHTTP for TrustchainHTTPHandler {
    async fn resolve_chain(did: &str) -> DIDChainResolutionResult {
        debug!("Resolving chain...");

        // Trustchain verify the issued credential
        let mut verifier = IONVerifier::new(get_ion_resolver("http://localhost:3000/"));

        debug!("Created verifier...");
        // TODO: Decide whether to pass root_timestamp as argument to api, or use a server config
        let result = verifier.verify(did, core_config().root_event_time).await;

        debug!("Verified did...");
        debug!("{:?}", result);
        let chain = match result {
            Ok(chain) => chain,
            _ => panic!(),
        };
        // Convert DID chain to vec of ResolutionResults
        DIDChainResolutionResult::new(&chain)
    }

    async fn resolve_did(did: &str) -> Result<ResolutionResult, TrustchainHTTPError> {
        debug!("Resolving...");
        let resolver = IONResolver::from(SidetreeClient::<ION>::new(Some(String::from(
            "http://localhost:3000/",
        ))));
        debug!("Created resolver");
        let result = resolver
            .resolve_as_result(did)
            .await
            .map_err(|_| TrustchainHTTPError::InternalError)?;
        debug!("Resolved result");
        match result {
            (_, Some(doc), Some(doc_meta)) => Ok(Self::to_resolution_result(doc, doc_meta)),
            _ => Err(TrustchainHTTPError::InternalError),
        }
    }

    fn resolve_bundle(did: &str) {
        todo!()
    }
}

impl TrustchainHTTPHandler {
    /// Handles get request for DID chain resolution.
    pub async fn get_did_chain(Path(did): Path<String>) -> impl IntoResponse {
        debug!("Received DID to get trustchain: {}", did.as_str());
        let chain_resolution = TrustchainHTTPHandler::resolve_chain(&did).await;
        (StatusCode::OK, Json(chain_resolution))
    }
    /// Handles get request for DID resolve API.
    pub async fn get_did_resolver(Path(did): Path<String>) -> impl IntoResponse {
        debug!("Received DID to resolve: {}", did.as_str());
        match TrustchainHTTPHandler::resolve_did(did.as_str()).await {
            Ok(resolved_json) => (StatusCode::OK, Json(resolved_json)),
            Err(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ResolutionResult::empty_response()),
            ),
        }
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

// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[tokio::test]
//     async fn test_get_did_resolver() {
//         let response = TrustchainHTTPHandler::get_did_resolver(Path("/did/did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q".to_string()))
//             .await
//             .into_response();

//         let status = response.status().clone();
//         let body_str = String::from_utf8(hyper::body::to_bytes(response.into_body()).await.unwrap().to_vec()).unwrap();

//         assert_eq!(status, StatusCode::OK);

//         assert_eq!(canonicalize(&body_str).unwrap(), canonicalize(TEST_ROOT_PLUS_2_RESOLVED).unwrap())
//     }
// }
