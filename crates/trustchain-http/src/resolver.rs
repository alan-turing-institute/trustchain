//! Handlers and trait for resolving Trustchain DIDs, chains and bundles.
use crate::errors::TrustchainHTTPError;
use crate::state::AppState;
use async_trait::async_trait;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use log::debug;
use serde::{Deserialize, Serialize};
use ssi::did_resolve::DIDResolver;
use ssi::{
    did::Document,
    did_resolve::{DocumentMetadata, ResolutionResult},
};
use std::sync::Arc;
use trustchain_core::chain::{Chain, DIDChain};
use trustchain_core::resolver::TrustchainResolver;
use trustchain_core::verifier::{Timestamp, Verifier, VerifierError};
use trustchain_ion::verifier::{TrustchainVerifier, VerificationBundle};

/// A HTTP API for resolving DID documents, chains, and verification bundles.
#[async_trait]
pub trait TrustchainHTTP {
    /// Resolves a DID document.
    async fn resolve_did(
        did: &str,
        resolver: &dyn TrustchainResolver,
    ) -> Result<ResolutionResult, TrustchainHTTPError>;

    /// Resolves a DID chain.
    async fn resolve_chain<T: DIDResolver + Send + Sync>(
        did: &str,
        verifier: &TrustchainVerifier<T>,
        root_event_time: Timestamp,
    ) -> Result<DIDChainResolutionResult, TrustchainHTTPError>;

    /// Resolves a DID verification bundle.
    async fn resolve_bundle<T: DIDResolver + Send + Sync>(
        did: &str,
        verifier: &TrustchainVerifier<T>,
    ) -> Result<VerificationBundle, TrustchainHTTPError>;
}

/// Type for implementing handlers for resolution of DID documents, chains, and bundles.
pub struct TrustchainHTTPHandler {}

#[async_trait]
impl TrustchainHTTP for TrustchainHTTPHandler {
    async fn resolve_did(
        did: &str,
        resolver: &dyn TrustchainResolver,
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
        verifier: &TrustchainVerifier<T>,
        root_event_time: Timestamp,
    ) -> Result<DIDChainResolutionResult, TrustchainHTTPError> {
        debug!("Verifying...");
        let chain = verifier
            .verify(did, root_event_time)
            .await
            // Any commitment error implies invalid root
            .map_err(|err| match err {
                err @ VerifierError::CommitmentFailure(_) => VerifierError::InvalidRoot(err.into()),
                err => err,
            })?;
        debug!("Verified did...");
        Ok(DIDChainResolutionResult::new(&chain))
    }

    async fn resolve_bundle<T: DIDResolver + Send + Sync>(
        did: &str,
        verifier: &TrustchainVerifier<T>,
    ) -> Result<VerificationBundle, TrustchainHTTPError> {
        let bundle = verifier.verification_bundle(did).await?;
        Ok((*bundle).clone())
    }
}

#[derive(Deserialize, Serialize, Debug)]
/// Struct for deserializing `root_event_time` from handler's query param.
pub struct RootEventTime {
    pub root_event_time: Timestamp,
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
        TrustchainHTTPHandler::resolve_chain(
            &did,
            &app_state.verifier,
            root_event_time.root_event_time,
        )
        .await
        .map(|chain| (StatusCode::OK, Json(chain)))
    }
    /// Handles get request for DID verification bundle resolution
    pub async fn get_verification_bundle(
        Path(did): Path<String>,
        State(app_state): State<Arc<AppState>>,
    ) -> impl IntoResponse {
        debug!("Received DID to get verification bundle: {}", did.as_str());
        TrustchainHTTPHandler::resolve_bundle(&did, &app_state.verifier)
            .await
            .map(|bundle| (StatusCode::OK, Json(bundle)))
    }
    /// Converts a DID document and metadata to a `ResolutionResult` type.
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
/// Type for converting a `DIDChain` to a chain of DID documents with [W3C](https://w3c-ccg.github.io/did-resolution/#did-resolution-result)
/// data structure.
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
    use super::*;
    use crate::{
        config::HTTPConfig,
        data::{
            TESTNET4_TEST_ROOT_PLUS_2_BUNDLE, TESTNET4_TEST_ROOT_PLUS_2_CHAIN,
            TESTNET4_TEST_ROOT_PLUS_2_RESOLVED, TEST_ROOT_PLUS_2_BUNDLE, TEST_ROOT_PLUS_2_CHAIN,
            TEST_ROOT_PLUS_2_RESOLVED,
        },
        server::TrustchainRouter,
    };
    use axum_test_helper::TestClient;
    use bitcoin::Network;
    use hyper::Server;
    use std::net::TcpListener;
    use tower::make::Shared;
    use trustchain_core::utils::canonicalize_str;
    use trustchain_ion::{trustchain_resolver_light_client, utils::BITCOIN_NETWORK};

    #[tokio::test]
    #[ignore = "requires TRUSTCHAIN_DATA and TRUSTCHAIN_CONFIG environment variables"]
    async fn test_not_found() {
        let app = TrustchainRouter::from(HTTPConfig::default()).into_router();
        let uri = "/nonexistent-path".to_string();
        let client = TestClient::new(app);
        let response = client.get(&uri).send().await;
        assert_eq!(response.status(), 404);
    }

    #[tokio::test]
    #[ignore = "requires ION, MongoDB, IPFS and Bitcoin RPC"]
    async fn test_resolve_did() {
        let app = TrustchainRouter::from(HTTPConfig::default()).into_router();

        let uri = match BITCOIN_NETWORK
            .as_ref()
            .expect("Integration test requires Bitcoin")
        {
            Network::Testnet => {
                "/did/did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q".to_string()
            }
            Network::Testnet4 => {
                "/did/did:ion:test:EiCMPaKNeI1AMj_tdPXRtV2PmAA3FemrqsTexloHKyTybg".to_string()
            }
            network @ _ => {
                panic!("No test fixtures for network: {:?}", network);
            }
        };
        let client = TestClient::new(app);
        let response = client.get(&uri).send().await;
        assert_eq!(response.status(), StatusCode::OK);

        let resolved_did_doc = match BITCOIN_NETWORK
            .as_ref()
            .expect("Integration test requires Bitcoin")
        {
            Network::Testnet => TEST_ROOT_PLUS_2_RESOLVED,
            Network::Testnet4 => TESTNET4_TEST_ROOT_PLUS_2_RESOLVED,
            network @ _ => {
                panic!("No test fixtures for network: {:?}", network);
            }
        };

        assert_eq!(
            canonicalize_str::<ResolutionResult>(&response.text().await).unwrap(),
            canonicalize_str::<ResolutionResult>(resolved_did_doc).unwrap()
        );
        let invalid_uri =
            "/did/did:ion:test:invalid_did__AsM3tgCut3OiBY4ekHTf__invalid_did".to_string();
        let response = client.get(&invalid_uri).send().await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        assert_eq!(
            response.text().await,
            r#"{"error":"DID: did:ion:test:invalid_did__AsM3tgCut3OiBY4ekHTf__invalid_did does not have a valid ION suffix with error: Decode Base64"}"#
        )
    }

    #[tokio::test]
    #[ignore = "requires ION, MongoDB, IPFS and Bitcoin RPC"]
    async fn test_resolve_chain() {
        let app = TrustchainRouter::from(HTTPConfig::default()).into_router();

        let uri = match BITCOIN_NETWORK
            .as_ref()
            .expect("Integration test requires Bitcoin")
        {
            Network::Testnet => format!("/did/chain/did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q?root_event_time=1666265405"),
            Network::Testnet4 => format!("/did/chain/did:ion:test:EiCMPaKNeI1AMj_tdPXRtV2PmAA3FemrqsTexloHKyTybg?root_event_time=1766953540"),
            network @ _ => {
                panic!("No test fixtures for network: {:?}", network);
            }
        };
        let expected_chain = match BITCOIN_NETWORK
            .as_ref()
            .expect("Integration test requires Bitcoin")
        {
            Network::Testnet => TEST_ROOT_PLUS_2_CHAIN,
            Network::Testnet4 => TESTNET4_TEST_ROOT_PLUS_2_CHAIN,
            network @ _ => {
                panic!("No test fixtures for network: {:?}", network);
            }
        };

        // let root_event_time = 1666265405;
        // let uri = format!("/did/chain/did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q?root_event_time={root_event_time}");
        let client = TestClient::new(app);
        let response = client.get(&uri).send().await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            canonicalize_str::<DIDChainResolutionResult>(&response.text().await).unwrap(),
            canonicalize_str::<DIDChainResolutionResult>(expected_chain).unwrap()
        );

        // Test for case where incorrect root_event_time for the root of the given DID, expected to
        // return Ok but with a JSON containing the wrapped Trustchain error.
        let uri_incorrect_root_event_time = match BITCOIN_NETWORK
            .as_ref()
            .expect("Integration test requires Bitcoin")
        {
            Network::Testnet => format!(
            "/did/chain/did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q?root_event_time=1234500"
        ).to_string(),
            Network::Testnet4 => format!(
            "/did/chain/did:ion:test:EiCMPaKNeI1AMj_tdPXRtV2PmAA3FemrqsTexloHKyTybg?root_event_time=1234500"
        ).to_string(),
            network @ _ => {
                panic!("No test fixtures for network: {:?}", network);
            }
        };
        let response = client.get(&uri_incorrect_root_event_time).send().await;
        assert_eq!(response.status(), StatusCode::OK);
        // A wrapped CommitmentError is now returned here mapped to VerifierError::InvalidRoot
        // println!("{}", response.text().await);
        assert!(response
            .text()
            .await
            .starts_with(r#"{"error":"Trustchain Verifier error: Invalid root DID error:"#),)
    }

    #[tokio::test]
    #[ignore = "requires ION, MongoDB, IPFS and Bitcoin RPC"]
    // Test of the bundle endpoint by using the verifier `fetch_bundle()` method to get from the endpoint
    async fn test_get_bundle() {
        let app = TrustchainRouter::from(HTTPConfig::default()).into_router();

        let uri = match BITCOIN_NETWORK
            .as_ref()
            .expect("Integration test requires Bitcoin")
        {
            Network::Testnet => format!("/did/bundle/did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q?root_event_time=1666265405"),
            Network::Testnet4 => format!("/did/bundle/did:ion:test:EiCMPaKNeI1AMj_tdPXRtV2PmAA3FemrqsTexloHKyTybg?root_event_time=1766953540"),
            network @ _ => {
                panic!("No test fixtures for network: {:?}", network);
            }
        };
        let client = TestClient::new(app);
        let response = client.get(&uri).send().await;
        assert_eq!(response.status(), StatusCode::OK);

        let expected_bundle = match BITCOIN_NETWORK
            .as_ref()
            .expect("Integration test requires Bitcoin")
        {
            Network::Testnet => TEST_ROOT_PLUS_2_BUNDLE,
            Network::Testnet4 => TESTNET4_TEST_ROOT_PLUS_2_BUNDLE,
            network @ _ => {
                panic!("No test fixtures for network: {:?}", network);
            }
        };

        assert_eq!(
            canonicalize_str::<VerificationBundle>(&response.text().await).unwrap(),
            canonicalize_str::<VerificationBundle>(expected_bundle).unwrap()
        );
        // Failing test for non-existent DID
        let uri =
            "/did/bundle/did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65A".to_string();
        let response = client.get(&uri).send().await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            response.text().await,
            r#"{"error":"Trustchain Verifier error: A resolver error during verification: DID: did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65A is not found."}"#
                .to_string()
        );
    }

    #[tokio::test]
    #[ignore = "requires ION, MongoDB, IPFS and Bitcoin RPC"]
    // Test of the bundle endpoint by using the verifier `fetch_bundle()` method to get from the endpoint
    async fn test_fetch_bundle() {
        // Using internals of the `TestClient` to make address available in test
        let listener = TcpListener::bind("127.0.0.1:0").expect("Could not bind ephemeral socket");
        let addr = listener.local_addr().unwrap();
        let port = addr.port();
        let http_config = HTTPConfig {
            port,
            ..Default::default()
        };
        assert_eq!(http_config.host.to_string(), addr.ip().to_string());

        // Run server
        tokio::spawn(async move {
            let server = Server::from_tcp(listener).unwrap().serve(Shared::new(
                TrustchainRouter::from(http_config).into_router(),
            ));
            server.await.expect("server error");
        });

        // Make a verifier instance and fetch bundle from server bundle endpoint
        let trustchain_endpoint = format!("http://127.0.0.1:{}/", port);
        let verifier = TrustchainVerifier::with_endpoint(
            trustchain_resolver_light_client(&trustchain_endpoint),
            trustchain_endpoint,
        );

        let (did, other_did) = match BITCOIN_NETWORK
            .as_ref()
            .expect("Integration test requires Bitcoin")
        {
            Network::Testnet => (
                "did:ion:test:EiBcLZcELCKKtmun_CUImSlb2wcxK5eM8YXSq3MrqNe5wA",
                "did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q",
            ),
            Network::Testnet4 => (
                "did:ion:test:EiA-CAfMgrNRa2Gv5D8ZF7AazX9nKxnSlYkYViuKeomymw",
                "did:ion:test:EiCKLQjzVNl0R7UCUW74JH_FN5VyfxWpL1IX1FUYTJ4uIA",
            ),
            network @ _ => {
                panic!("No test fixtures for network: {:?}", network);
            }
        };
        let (root_event_time, other_root_event_time) = match BITCOIN_NETWORK
            .as_ref()
            .expect("Integration test requires Bitcoin")
        {
            Network::Testnet => (1666971942, 1666265405),
            Network::Testnet4 => (1766953540, 1753028520),
            network @ _ => {
                panic!("No test fixtures for network: {:?}", network);
            }
        };

        // Check verification
        verifier.verify(did, root_event_time).await.unwrap();
        // Check verification for another root
        verifier
            .verify(other_did, other_root_event_time)
            .await
            .unwrap();
    }
}
