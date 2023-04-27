use axum::{routing::get, Router};
use clap::Parser;
use ssi::did_resolve::ResolutionResult;
use trustchain_http::data::TEST_ROOT_PLUS_2_RESOLVED;
use trustchain_http::{config::ServerConfig, handlers, issuer, resolver, verifier};

// Setup based on https://github.com/spruceid/didkit/blob/main/http/tests/main.rs

fn serve() -> (String, impl FnOnce()) {
    // TODO: Wrap and import this for reuse here and in main - add get_app to lib.rs
    let config: ServerConfig = Parser::parse();

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
            get(resolver::TrustchainHTTPHandler::get_did_resolver),
        )
        .route(
            "/did/chain/:id",
            get(resolver::TrustchainHTTPHandler::get_did_chain),
        )
        .with_state(config);

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
    let (base, shutdown) = serve();
    let client = hyper::Client::builder().build_http::<hyper::Body>();
    let uri = (base + "/nonexistent-path").parse::<hyper::Uri>().unwrap();
    let resp = client.get(uri).await.unwrap();
    assert_eq!(resp.status(), 404);

    shutdown();
}

#[tokio::test]
async fn resolve_did() {
    let expected_body = TEST_ROOT_PLUS_2_RESOLVED;

    let (base, shutdown) = serve();
    let client = hyper::Client::builder().build_http::<hyper::Body>();
    let uri = (base + "/did/did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q")
        .parse::<hyper::Uri>()
        .unwrap();
    let resp = client.get(uri).await.unwrap();
    let body_str = String::from_utf8(
        hyper::body::to_bytes(resp.into_body())
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    let body_res_result: ResolutionResult = serde_json::from_str(&body_str).unwrap();
    println!("{}", body_str);
    assert_eq!(
        serde_json::to_string(&body_res_result).unwrap(),
        serde_json::to_string(&serde_json::from_str::<ResolutionResult>(expected_body).unwrap())
            .unwrap()
    );
    shutdown();
}
