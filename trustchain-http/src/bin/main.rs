use log::info;
use trustchain_http::config::{http_config, HTTP_CONFIG};
use trustchain_http::server;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Get config from CLI
    let config = HTTP_CONFIG.clone();

    // Print config
    info!("{}", config);

    // Run server
    match http_config().https {
        false => server::http_server(config).await.unwrap(),
        true => server::https_server(config).await.unwrap(),
    }

    Ok(())
}
