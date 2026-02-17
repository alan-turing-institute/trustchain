use log::info;
use trustchain_rpc::config::RPC_CONFIG;
use trustchain_rpc::server::run_server;

use jsonrpsee::core::client::ClientT;
use jsonrpsee::http_client::HttpClient;
use jsonrpsee::rpc_params;
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

    // Print config
    info!("{}", config);

    let (server_addr, handle) = run_server(config).await?;

    // TODO: log an info level message here to indicate that the server has started
    // (similar to trustchain-http main).

    let url = format!("http://{}", server_addr);
    let client = HttpClient::builder().build(url)?;
    let params = rpc_params![1_u64, 2, 3];
    let response: Result<String, _> = client.request("say_hello", params).await;
    tracing::info!("r: {:?}", response);

    // Await a CTRL+C event, so the RPC server stays up until manually stopped.
    tokio::signal::ctrl_c().await?;
    handle.stop().unwrap();
    handle.stopped().await;

    Ok(())
}
