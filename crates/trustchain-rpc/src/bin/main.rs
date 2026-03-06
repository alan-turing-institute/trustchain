use log::info;
use trustchain_rpc::config::RPC_CONFIG;
use trustchain_rpc::server::run_server;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Get config and write to log.
    let config = RPC_CONFIG.clone();
    info!("{}", config);

    let (server_addr, handle) = run_server(config).await?;

    info!("RPC server started on {}", server_addr);

    // Await a CTRL+C event, so the RPC server stays up until manually stopped.
    tokio::signal::ctrl_c().await?;
    info!("Stopping RPC server...");
    handle.stop().unwrap();
    handle.stopped().await;

    Ok(())
}
