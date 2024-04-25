use crate::attestor;
use crate::config::http_config;
use crate::middleware::validate_did;
use crate::{
    config::HTTPConfig, issuer, resolver, root, state::AppState, static_handlers, verifier,
};
use axum::routing::{post, IntoMakeService};
use axum::{middleware, routing::get, Router};
use axum_server::tls_rustls::RustlsConfig;
use hyper::server::conn::AddrIncoming;
use std::path::PathBuf;
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
                .route("/", get(static_handlers::index))
                .route(
                    "/issuer/:id",
                    get(issuer::TrustchainIssuerHTTPHandler::get_issuer_qrcode),
                )
                .route(
                    "/issuer_rss/:id",
                    get(issuer::TrustchainIssuerHTTPHandler::get_issuer_qrcode_rss),
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
                            issuer::TrustchainIssuerHTTPHandler::post_issuer(
                                (id, vc_info),
                                state,
                                false,
                            )
                        }
                    }),
                )
                .route(
                    "/vc_rss/issuer/:id",
                    get(issuer::TrustchainIssuerHTTPHandler::get_issuer).post({
                        let state = shared_state.clone();
                        move |(id, vc_info)| {
                            issuer::TrustchainIssuerHTTPHandler::post_issuer(
                                (id, vc_info),
                                state,
                                true,
                            )
                        }
                    }),
                )
                .route(
                    "/vc/verifier/:id",
                    get(verifier::TrustchainVerifierHTTPHandler::get_verifier).post({
                        let state = shared_state.clone();
                        move |verification_info| {
                            verifier::TrustchainVerifierHTTPHandler::post_verifier(
                                verification_info,
                                state,
                            )
                        }
                    }),
                )
                .route(
                    "/did/:id",
                    get(resolver::TrustchainHTTPHandler::get_did_resolution)
                        .layer(ServiceBuilder::new().layer(middleware::from_fn(validate_did))),
                )
                // Duplicate `did` and `identifier` routes as the resolver expects a
                // `SidetreeClient` that can resolve at route `<ENDPOINT>/identifiers/<DID>`:
                // See [here](https://docs.rs/did-ion/0.1.0/src/did_ion/sidetree.rs.html#1392-1400).
                .route(
                    "/identifiers/:id",
                    get(resolver::TrustchainHTTPHandler::get_did_resolution)
                        .layer(ServiceBuilder::new().layer(middleware::from_fn(validate_did))),
                )
                .route(
                    "/did/chain/:id",
                    get(resolver::TrustchainHTTPHandler::get_chain_resolution)
                        .layer(ServiceBuilder::new().layer(middleware::from_fn(validate_did))),
                )
                .route(
                    "/did/bundle/:id",
                    get(resolver::TrustchainHTTPHandler::get_verification_bundle)
                        .layer(ServiceBuilder::new().layer(middleware::from_fn(validate_did))),
                )
                .route(
                    "/root",
                    get(root::TrustchainRootHTTPHandler::get_root_candidates),
                )
                .route(
                    "/root/timestamp/:height",
                    get(root::TrustchainRootHTTPHandler::get_block_timestamp),
                )
                .route(
                    "/operations",
                    post({
                        let state = shared_state.clone();
                        move |operation| crate::ion::post_operation(operation, state)
                    }),
                )
                .route(
                    "/did/attestor/identity/initiate",
                    post(attestor::TrustchainAttestorHTTPHandler::post_identity_initiation),
                )
                .route(
                    "/did/attestor/identity/respond/:key_id",
                    // post(attestor::TrustchainAttestorHTTPHandler::post_response),
                    post({
                        let state = shared_state.clone();
                        move |key_id| {
                            attestor::TrustchainAttestorHTTPHandler::post_identity_response(
                                key_id, state,
                            )
                        }
                    }),
                )
                .route(
                    "/did/attestor/content/initiate/:key_id",
                    // post(attestor::TrustchainAttestorHTTPHandler::post_content_initiation),
                    post({
                        let state = shared_state.clone();
                        move |(key_id, ddid)| {
                            attestor::TrustchainAttestorHTTPHandler::post_content_initiation(
                                (key_id, ddid),
                                state,
                            )
                        }
                    }),
                )
                .route(
                    "/did/attestor/content/respond/:key_id",
                    post({
                        let state = shared_state.clone();
                        move |key_id| {
                            attestor::TrustchainAttestorHTTPHandler::post_content_response(
                                key_id, state,
                            )
                        }
                    }),
                )
                .with_state(shared_state),
        }
    }

    /// Moves wrapped app router and consumes.
    pub fn into_router(self) -> Router {
        self.router
    }
}

/// Spawns a Trustchain server given `HTTPConfig` with http.
pub fn http_server(config: HTTPConfig) -> axum::Server<AddrIncoming, IntoMakeService<Router>> {
    let addr = config.to_socket_address();
    let shared_state = Arc::new(AppState::new(config));
    let app = TrustchainRouter::from(shared_state).into_router();
    axum::Server::bind(&addr).serve(app.into_make_service())
}

/// Spawns a Trustchain server given `HTTPConfig` with https.
pub async fn https_server(config: HTTPConfig) -> std::io::Result<()> {
    let addr = config.to_socket_address();
    let shared_state = Arc::new(AppState::new(config));
    let app = TrustchainRouter::from(shared_state).into_router();
    let tls_config = rustls_config(http_config().https_path.as_ref().unwrap()).await;
    axum_server::bind_rustls(addr, tls_config)
        .serve(app.into_make_service())
        .await
}

/// Generates a `RustlsConfig` for https servers given a path with certificate and key. Based on
/// axum [example](https://github.com/tokio-rs/axum/blob/d30375925dd22cc44aeaae2871f8ead1630fadf8/examples/tls-rustls/src/main.rs).
async fn rustls_config(path: &str) -> RustlsConfig {
    // Configure certificate and private key used by https
    let path = shellexpand::tilde(path);
    RustlsConfig::from_pem_file(
        PathBuf::from(path.as_ref()).join("cert.pem"),
        PathBuf::from(path.as_ref()).join("key.pem"),
    )
    .await
    .expect("Failed to create Rustls config.")
}
