use axum::{routing::get, Router};
use clap::Parser;
use log::info;
use trustchain_issuer_backend::{config::ServerConfig, handlers};

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

    // Build our application with a route
    let app = Router::new()
        .route("/", get(handlers::index))
        .route("/issuer", get(handlers::get_issuer_qrcode))
        .route("/verifier", get(handlers::get_verifier_qrcode))
        .route(
            "/vc/issuer/:id",
            get(handlers::get_issuer).post(handlers::post_issuer),
        )
        .route(
            "/vc/verifier",
            get(handlers::get_verifier).post(handlers::post_verifier),
        )
        .route("/did/:id", get(handlers::get_did_resolver))
        .route(
            "/did/chain/:id",
            get(handlers::MyExampleHttp::get_did_chain),
        )
        .with_state(config.clone());

    // Address
    let addr = format!("{}:{}", config.host, config.port).parse().unwrap();

    // Logging
    tracing::debug!("listening on {}", addr);

    // Run server
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
    Ok(())
}
