use axum::{routing::get, Router};
use ssi::did_resolve::ResolutionResult;
use std::sync::Arc;
use trustchain_core::utils::canonicalize;
use trustchain_http::data::TEST_ROOT_PLUS_2_RESOLVED;
use trustchain_http::state::AppState;
use trustchain_http::{config::ServerConfig, handlers, issuer, resolver, verifier};

// Setup based on https://github.com/spruceid/didkit/blob/main/http/tests/main.rs

// TODO: Wrap and import this for reuse here and in main - add get_app to lib.rs
fn serve(config: ServerConfig) -> (String, impl FnOnce()) {
    let shared_state = Arc::new(AppState::new(config));
    let app = Router::new()
        .route("/", get(handlers::index))
        .route(
            "/issuer",
            get(issuer::TrustchainIssuerHTTPHandler::get_issuer_qrcode),
        )
        .route(
            "/verifier",
            get(verifier::TrustchainVerifierHTTPHandler::get_verifier_qrcode),
        )
        .route(
            "/vc/issuer/:id",
            get(issuer::TrustchainIssuerHTTPHandler::get_issuer)
                .post(issuer::TrustchainIssuerHTTPHandler::post_issuer),
        )
        .route(
            "/vc/verifier",
            get(verifier::TrustchainVerifierHTTPHandler::get_verifier)
                .post(verifier::TrustchainVerifierHTTPHandler::post_verifier),
        )
        .route(
            "/did/:id",
            get(resolver::TrustchainHTTPHandler::get_did_resolution),
        )
        .route(
            "/did/chain/:id",
            get(resolver::TrustchainHTTPHandler::get_chain_resolution),
        )
        .with_state(shared_state);

    let addr = ([127, 0, 0, 1], 0).into();
    let server = axum::Server::bind(&addr).serve(app.into_make_service());
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

#[tokio::test]
async fn not_found() {
    let (base, shutdown) = serve(ServerConfig::default());
    let client = hyper::Client::builder().build_http::<hyper::Body>();
    let uri = (base + "/nonexistent-path").parse::<hyper::Uri>().unwrap();
    let resp = client.get(uri).await.unwrap();
    assert_eq!(resp.status(), 404);

    shutdown();
}

#[tokio::test]
async fn resolve_did() {
    let expected = TEST_ROOT_PLUS_2_RESOLVED;
    let (base, shutdown) = serve(ServerConfig::default());
    let uri = format!("{base}/did/did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q");
    let actual = serde_json::from_str::<ResolutionResult>(
        &reqwest::get(&uri).await.unwrap().text().await.unwrap(),
    )
    .unwrap();
    assert_eq!(canonicalize(&actual).unwrap(), expected);
    shutdown();
}
