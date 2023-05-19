use axum::{routing::get, Router};
use ssi::did_resolve::ResolutionResult;
use std::sync::Arc;
use trustchain_core::utils::canonicalize;
use trustchain_http::data::TEST_ROOT_PLUS_2_RESOLVED;
use trustchain_http::server;
use trustchain_http::state::AppState;
use trustchain_http::{config::ServerConfig, handlers, issuer, resolver, verifier};

// Resolution integration tests
#[tokio::test]
async fn test_not_found() {
    let (base, shutdown) = server::serve(ServerConfig::default());
    let client = hyper::Client::builder().build_http::<hyper::Body>();
    let uri = (base + "/nonexistent-path").parse::<hyper::Uri>().unwrap();
    let resp = client.get(uri).await.unwrap();
    assert_eq!(resp.status(), 404);

    shutdown();
}

#[tokio::test]
#[ignore = "integration test requires ION, MongoDB, IPFS and Bitcoin RPC"]
async fn test_resolve_did() {
    let expected = TEST_ROOT_PLUS_2_RESOLVED;
    let (base, shutdown) = server::serve(ServerConfig::default());
    let uri = format!("{base}/did/did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q");
    let actual = serde_json::from_str::<ResolutionResult>(
        &reqwest::get(&uri).await.unwrap().text().await.unwrap(),
    )
    .unwrap();
    assert_eq!(canonicalize(&actual).unwrap(), expected);
    shutdown();
}

#[tokio::test]
#[ignore = "integration test requires ION, MongoDB, IPFS and Bitcoin RPC"]
async fn test_resolve_chain() {
    todo!("Implement a test of the chain endpoint handler.")
}

#[tokio::test]
#[ignore = "integration test requires ION, MongoDB, IPFS and Bitcoin RPC"]
async fn test_resolve_bundle() {
    todo!("Implement a test of the bundle endpoint handler.")
}

// Issuer integration tests
#[tokio::test]
#[ignore = "integration test requires ION, MongoDB, IPFS and Bitcoin RPC"]
async fn test_get_issuer_offer() {
    todo!()
}

#[tokio::test]
#[ignore = "integration test requires ION, MongoDB, IPFS and Bitcoin RPC"]
async fn test_post_issuer_credential() {
    todo!()
}

// Verifier integration tests
#[tokio::test]
#[ignore = "integration test requires ION, MongoDB, IPFS and Bitcoin RPC"]
async fn test_get_verifier_request() {
    todo!()
}

#[tokio::test]
#[ignore = "integration test requires ION, MongoDB, IPFS and Bitcoin RPC"]
async fn test_post_verifier_credential() {
    todo!()
}
