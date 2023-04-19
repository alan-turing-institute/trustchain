use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse};
use core::time;
use log::info;
use serde::{Deserialize, Serialize};
use serde_json::to_string_pretty;
use ssi::{
    did::Document,
    did_resolve::{DocumentMetadata, ResolutionResult},
};
use trustchain_core::data::{TEST_ROOT_PLUS_2_DOCUMENT, TEST_ROOT_PLUS_2_DOCUMENT_METADATA};
use trustchain_core::{
    chain::{Chain, DIDChain},
    ROOT_EVENT_TIME_2378493,
};

use crate::data::TEST_CHAIN;

use did_ion::{sidetree::SidetreeClient, ION};
use trustchain_core::verifier::Verifier;
use trustchain_ion::verifier::IONVerifier;
use trustchain_ion::{get_ion_resolver, IONResolver};

pub trait TrustchainHTTP {
    /// Resolves a DID chain, will this include the bundle?
    fn resolve_chain(did: &str) -> DIDChainResolutionResult;

    /// Resolves a DID chain, will this include the bundle?
    fn resolve_did(did: &str) -> ResolutionResult;

    // TODO: should we include a separate method to return verification bundle?
    fn resolve_bundle(did: &str);
}

pub struct TrustchainHTTPHandler {}

impl TrustchainHTTP for TrustchainHTTPHandler {
    fn resolve_chain(did: &str) -> DIDChainResolutionResult {
        info!("Resolving chain...");

        // // Trustchain verify the issued credential
        // let verifier = IONVerifier::new(get_ion_resolver("http://localhost:3000/"));

        // info!("Created verifier...");
        // // TODO: Decide whether to pass root_timestamp as argument to api, or use a server config
        // // TODO: This currently causes an error: `'Cannot start a runtime from within a runtime...`
        // //       The `runtime` that is being called in the resolver is being called from within the
        // //       wider htttp `main` runtime.
        // let result = verifier.verify(did, ROOT_EVENT_TIME_2378493);

        // info!("Verified did...");
        // let chain = match result {
        //     Ok(chain) => chain,
        //     _ => panic!()
        // };

        // Currently just returns a static string for initial testing
        let chain: DIDChain = serde_json::from_str(TEST_CHAIN).unwrap();

        // Convert DID chain to vec of ResolutionResults
        DIDChainResolutionResult::new(&chain)
    }

    fn resolve_did(did: &str) -> ResolutionResult {
        info!("Resolving...");
        let resolver = IONResolver::from(SidetreeClient::<ION>::new(Some(String::from(
            "http://localhost:3000/",
        ))));
        info!("Created resolver");
        // Result metadata, Document, Document metadata
        let result = resolver.resolve_as_result(did);
        info!("Resolved result");
        let (res_meta, result_doc, result_doc_meta) = match result {
            Ok(x) => x,
            Err(e) => panic!(),
        };
        let (doc, doc_meta) = match (result_doc, result_doc_meta) {
            (Some(x), Some(y)) => (x, y),
            _ => panic!(),
        };
        to_resolution_result(doc, doc_meta)
    }

    fn resolve_bundle(did: &str) {
        todo!()
    }
}

impl TrustchainHTTPHandler {
    pub async fn get_did_chain(Path(did): Path<String>) -> impl IntoResponse {
        info!("Received DID to get trustchain: {}", did.as_str());

        // TODO: implement actual verification with trustchain-ion crate

        // Currently just returns a static string for initial testing
        let chain: DIDChain = serde_json::from_str(TEST_CHAIN).unwrap();

        // // Convert DID chain to vec of ResolutionResults
        let chain_resolution = DIDChainResolutionResult::new(&chain);

        // let chain_resolution = TrustchainHTTPHandler::resolve_chain(&did);

        (
            StatusCode::OK,
            Html(to_string_pretty(&chain_resolution).unwrap()),
        )
    }
}

// TODO: consider refactor into trait
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
                .map(|(doc, doc_meta)| to_resolution_result(doc, doc_meta))
                .collect::<Vec<_>>(),
        }
    }
}

// #[get("/did/{did}")]
pub async fn get_did_resolver(Path(did): Path<String>) -> impl IntoResponse {
    info!("Received DID to resolve: {}", did.as_str());

    // Currently just returns a static string for initial testing
    let doc = serde_json::from_str(TEST_ROOT_PLUS_2_DOCUMENT).unwrap();
    let doc_meta = serde_json::from_str(TEST_ROOT_PLUS_2_DOCUMENT_METADATA).unwrap();
    // // Use ResolutionResult struct
    let resolved_json = to_resolution_result(doc, doc_meta);

    // Call resolve_did() here instead of loading test documents
    // let resolved_json = TrustchainHTTPHandler::resolve_did(did.as_str());

    // Arbitrary delay for testing
    let delay = time::Duration::from_millis(500);
    std::thread::sleep(delay);
    (
        StatusCode::OK,
        Html(to_string_pretty(&resolved_json).unwrap()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_get_did_resolver() {
        let response = get_did_resolver(Path("/did/abc".to_string()))
            .await
            .into_response();

        let status = response.status().clone();
        let body = hyper::body::to_bytes(response.into_body()).await;
        let bytes = match body {
            Ok(bs) => bs,
            _ => panic!(),
        };

        assert_eq!(status, StatusCode::OK);

        //TODO: Load expected output from file
        assert_eq!(bytes, "error")
    }
}
