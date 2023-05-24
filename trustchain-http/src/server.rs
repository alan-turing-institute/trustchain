// use axum::{routing::get, Router, middleware::{self, Next}, extract::{FromRequest, Request}};
use crate::middleware::validate_did;
use crate::{config::ServerConfig, handlers, issuer, resolver, state::AppState, verifier};
use axum::routing::IntoMakeService;
use axum::{middleware, routing::get, Router};
use hyper::server::conn::AddrIncoming;
use std::sync::Arc;
use tower::ServiceBuilder;

pub struct TrustchainRouter {
    router: Router,
}

impl From<Arc<AppState>> for TrustchainRouter {
    fn from(app_state: Arc<AppState>) -> Self {
        Self {
            router: Self::generate_router(app_state),
        }
    }
}

impl From<ServerConfig> for TrustchainRouter {
    fn from(config: ServerConfig) -> Self {
        let app_state = Arc::new(AppState::new(config));
        Self {
            router: Self::generate_router(app_state),
        }
    }
}

impl TrustchainRouter {
    /// Constructs a router given a ServerConfig.
    fn generate_router(shared_state: Arc<AppState>) -> Router {
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
            .with_state(shared_state)
    }

    /// Moves wrapped app router and consumes.
    pub fn router(self) -> Router {
        self.router
    }
}

/// General method to spawn a Trustchain server given ServerConfig.
pub fn server(config: ServerConfig) -> axum::Server<AddrIncoming, IntoMakeService<Router>> {
    let addr = config.to_socket_address();
    let shared_state = Arc::new(AppState::new(config));
    let app = TrustchainRouter::from(shared_state).router();
    axum::Server::bind(&addr).serve(app.into_make_service())
}
