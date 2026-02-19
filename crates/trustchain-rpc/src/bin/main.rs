use log::info;
use trustchain_rpc::config::RPC_CONFIG;
use trustchain_rpc::server::run_server;

use tracing_subscriber::util::SubscriberInitExt;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()?
        .add_directive("jsonrpsee[method_call{name = \"say_hello\"}]=trace".parse()?);
    tracing_subscriber::FmtSubscriber::builder()
        .with_env_filter(filter)
        .finish()
        .try_init()?;

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
