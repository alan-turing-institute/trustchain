use log::info;
use trustchain_http::config::HTTP_CONFIG;
use trustchain_http::server;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Get config from CLI
    let config = HTTP_CONFIG.clone();

    // Print config
    info!("{}", config);
    let addr = config.to_address();

    // Init server
    server::server(config).await.unwrap();

    // Logging
    tracing::debug!("listening on {}", addr);

    Ok(())
}
