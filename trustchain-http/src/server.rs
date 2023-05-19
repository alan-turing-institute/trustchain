// use axum::{routing::get, Router, middleware::{self, Next}, extract::{FromRequest, Request}};
use crate::middleware::validate_did;
use crate::{config::ServerConfig, handlers, issuer, resolver, state::AppState, verifier};
use axum::{middleware, routing::get, Router};
use std::sync::Arc;
use tower::ServiceBuilder;

/// General method to spawn a Trustchain server given ServerConfig and create a shutdown closure for
/// use in binaries and tests. Setup based on [`didkit-http`](https://github.com/spruceid/didkit/blob/main/http/tests/main.rs).
pub fn serve(config: ServerConfig) -> (String, impl FnOnce()) {
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
            get(resolver::TrustchainHTTPHandler::get_did_resolution)
                .layer(ServiceBuilder::new().layer(middleware::from_fn(validate_did))),
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
