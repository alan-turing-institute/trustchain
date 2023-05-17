// use axum::{routing::get, Router, middleware::{self, Next}, extract::{FromRequest, Request}};
use axum::extract::{Path, Query, State};
use axum::{
    async_trait,
    body::Body,
    body::{self, BoxBody, Bytes, Full},
    extract::FromRequest,
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
    routing::post,
    Json, Router,
};
use clap::Parser;
use log::info;
use serde_json::json;
use std::sync::Arc;
use trustchain_http::{
    config::ServerConfig, handlers, issuer, resolver, state::AppState, verifier,
};
use trustchain_ion::config::ion_config;
// use tower_http::validate_request::{ValidateRequestHeaderLayer, ValidateRequest};
use tower::{service_fn, Service, ServiceBuilder};
use tower_http::ServiceBuilderExt;

// Process sketch:
// 1. User visits "/issuer" page, and is displayed a QR code of a URL (with UUID) to send GET
//    request to receive a credential offer.
// 2. Within credible app, scan QR code of address which performs GET
// 3. Server receives get request and returns a credential offer with UUID from URI
// 4. Credible receives offer and returns POST with any user info (i.e. the DID)
// 5. Server receives POST data, checks it is valid for UUID and returns a signed credential with offer
// 6. Credible receives response and verifies credential received using the Trustchain server

#[tokio::main]
async fn main() -> std::io::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Get config from CLI
    let config: ServerConfig = Parser::parse();

    // Print config
    info!("{}", config);

    // Address
    let addr = format!("{}:{}", config.host, config.port).parse().unwrap();

    // Create shared state
    let shared_state = Arc::new(AppState::new(config));

    // Build our application with a route
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
            "/did_test/:id",
            get(resolver::TrustchainHTTPHandler::get_did_resolution),
        )
        // TODO: add parsing of resolution request returning "BAD_REQUEST" if format incorrect using middleware
        .route(
            "/did/chain/:id",
            get(resolver::TrustchainHTTPHandler::get_chain_resolution),
        )
        .route(
            "/did/bundle/:id",
            get(resolver::TrustchainHTTPHandler::get_verification_bundle),
        )
        .with_state(shared_state);

    // Logging
    tracing::debug!("listening on {}", addr);

    // Run server
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
    Ok(())
}

// TODO: Move middleware to middleware module

// See example from axum: https://github.com/tokio-rs/axum/blob/v0.6.x/examples/consume-body-in-extractor-or-middleware/src/main.rs
// middleware that shows how to consume the request body upfront
async fn validate_did(
    Path(did): Path<String>,
    request: Request<Body>,
    next: Next<Body>,
) -> Result<impl IntoResponse, impl IntoResponse> {
    tracing::info!(did);
    // Validate length is 59 (testnet) or 54 (mainnet)
    if ion_config().mongo_database_ion_core.contains("testnet") && did.len() != 59 {
        let message = json!({
            "error":
                format!(
                    "DID: {} is incorrect length {}. Should be length 59.",
                    did,
                    did.len()
                )
        });
        return Err((StatusCode::BAD_REQUEST, Json(message)));
    } else if ion_config().mongo_database_ion_core.contains("mainnet") && did.len() != 54 {
        let message = json!({
            "error":
                format!(
                    "DID: {} is incorrect length {}. Should be length 54.",
                    did,
                    did.len()
                )
        });
        return Err((StatusCode::BAD_REQUEST, Json(message)));
    }
    Ok(next.run(request).await)
}
