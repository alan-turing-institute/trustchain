use crate::attestor;
// use axum::{routing::get, Router, middleware::{self, Next}, extract::{FromRequest, Request}};
use crate::middleware::validate_did;
use crate::{config::HTTPConfig, handlers, issuer, resolver, state::AppState, verifier};
use axum::routing::{post, IntoMakeService};
use axum::{middleware, routing::get, Router};
use hyper::server::conn::AddrIncoming;
use std::sync::Arc;
use tower::ServiceBuilder;

/// A wrapped axum router.
pub struct TrustchainRouter {
    router: Router,
}

impl From<Arc<AppState>> for TrustchainRouter {
    fn from(app_state: Arc<AppState>) -> Self {
        Self::new(app_state)
    }
}

impl From<HTTPConfig> for TrustchainRouter {
    fn from(config: HTTPConfig) -> Self {
        let app_state = Arc::new(AppState::new(config));
        Self::new(app_state)
    }
}

impl TrustchainRouter {
    /// Constructs a router given a ServerConfig.
    fn new(shared_state: Arc<AppState>) -> Self {
        Self {
            router: Router::new()
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
                    get(issuer::TrustchainIssuerHTTPHandler::get_issuer).post({
                        let state = shared_state.clone();
                        move |(id, vc_info)| {
                            issuer::TrustchainIssuerHTTPHandler::post_issuer((id, vc_info), state)
                        }
                    }),
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
                .route(
                    "/did/attestor/initiate",
                    post(attestor::TrustchainAttestorHTTPHandler::post_initiation),
                )
                .with_state(shared_state),
        }
    }

    /// Moves wrapped app router and consumes.
    pub fn into_router(self) -> Router {
        self.router
    }
}

/// General method to spawn a Trustchain server given ServerConfig.
pub fn server(config: HTTPConfig) -> axum::Server<AddrIncoming, IntoMakeService<Router>> {
    let addr = config.to_socket_address();
    let shared_state = Arc::new(AppState::new(config));
    let app = TrustchainRouter::from(shared_state).into_router();
    axum::Server::bind(&addr).serve(app.into_make_service())
}
