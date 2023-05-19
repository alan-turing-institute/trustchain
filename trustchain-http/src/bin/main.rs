// use axum::{routing::get, Router, middleware::{self, Next}, extract::{FromRequest, Request}};
use clap::Parser;
use log::info;
use trustchain_http::config::ServerConfig;
// use tower_http::validate_request::{ValidateRequestHeaderLayer, ValidateRequest};

use trustchain_http::server;

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
    let addr = config.to_address();

    // Init server
    server::server(config).await.unwrap();

    // Logging
    tracing::debug!("listening on {}", addr);

    Ok(())
}
