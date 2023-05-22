// use axum::{routing::get, Router, middleware::{self, Next}, extract::{FromRequest, Request}};
use crate::middleware::validate_did;
use crate::{config::ServerConfig, handlers, issuer, resolver, state::AppState, verifier};
use axum::routing::IntoMakeService;
use axum::{middleware, routing::get, Router};
use hyper::server::conn::AddrIncoming;
use std::sync::Arc;
use tower::ServiceBuilder;

/// Constructs a router given a ServerConfig.
pub fn router(config: ServerConfig) -> Router {
    let shared_state = Arc::new(AppState::new(config));
    Router::new()
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
        .route(
            "/did/bundle/:id",
            get(resolver::TrustchainHTTPHandler::get_verification_bundle),
        )
        .with_state(shared_state)
}

/// General method to spawn a Trustchain server given ServerConfig.
pub fn server(config: ServerConfig) -> axum::Server<AddrIncoming, IntoMakeService<Router>> {
    let addr = config.to_socket_address();
    let app = router(config);
    axum::Server::bind(&addr).serve(app.into_make_service())
}
