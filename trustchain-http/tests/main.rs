use axum::{routing::get, Router};
use ssi::did_resolve::ResolutionResult;
use std::sync::Arc;
use trustchain_core::utils::canonicalize;
use trustchain_http::data::{TEST_ROOT_PLUS_2_BUNDLE, TEST_ROOT_PLUS_2_RESOLVED};
use trustchain_http::server::server;
use trustchain_http::state::AppState;
use trustchain_http::{config::ServerConfig, handlers, issuer, resolver, verifier};
use trustchain_ion::verifier::VerificationBundle;

// TODO: identify how to set-up the graceful server (like init() in trustchain-core::utils) only once
// and shutdown only once at the end of all tests.
// For the time being: `cargo test -- --test-threads=1` so no multiple server issue.

/// Makes a server with graceful shutdown for tests.
fn server_graceful(config: ServerConfig) -> (String, impl FnOnce()) {
    let server = server(config);
    let url = "http://".to_string() + &server.local_addr().to_string();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let shutdown = || shutdown_tx.send(()).unwrap();
    let graceful = server.with_graceful_shutdown(async {
        shutdown_rx.await.unwrap();
    });
    tokio::task::spawn(async move {
        graceful.await.unwrap();
    });

    (url, shutdown)
}

// Resolution integration tests
#[tokio::test]
async fn test_not_found() {
    let (base, shutdown) = server_graceful(ServerConfig::default());
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
    let (base, shutdown) = server_graceful(ServerConfig::default());
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
// TODO: same format as resolve DID and bundle test
async fn test_resolve_chain() {
    // let (base, shutdown) = server_graceful(ServerConfig::default());
    // let uri =
    // format!("{base}/did/chain/did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q");
    // let actual = serde_json::from_str::<DIDChainResolutionResult>(
    //     &reqwest::get(&uri).await.unwrap().text().await.unwrap(),
    // )
    // .unwrap();
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

#[tokio::test]
// Test of the bundle endpoint by using the verifier `fetch_bundle()` method to get from the endpoint
async fn test_get_bundle() {
    let (base, shutdown) = server_graceful(ServerConfig::default());
    let uri =
        format!("{base}/did/bundle/did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q");
    let actual = serde_json::from_str::<VerificationBundle>(
        &reqwest::get(&uri).await.unwrap().text().await.unwrap(),
    )
    .unwrap();
    assert_eq!(
        canonicalize(&actual).unwrap(),
        canonicalize(&serde_json::from_str::<VerificationBundle>(TEST_ROOT_PLUS_2_BUNDLE).unwrap())
            .unwrap()
    );
    shutdown();
}

#[tokio::test]
// TODO: implement with server_graceful
// Test of the bundle endpoint by using the verifier `fetch_bundle()` method to get from the endpoint
async fn test_fetch_bundle() {
    // let verifier = IONVerifier::new(get_ion_resolver("http://localhost:3000"));
    // let did = "did:ion:test:EiBcLZcELCKKtmun_CUImSlb2wcxK5eM8YXSq3MrqNe5wA";

    // let result = verifier.fetch_bundle(did, Some("http://127.0.0.1:8081/did/bundle".to_string())).await;
    let result = serde_json::from_str::<VerificationBundle>(TEST_ROOT_PLUS_2_BUNDLE);
    println!("{:?}", result);
    assert!(result.is_ok());
}
