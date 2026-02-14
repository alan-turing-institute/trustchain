// use trustchain_api::{
//     api::{TrustchainDIDAPI, TrustchainDataAPI, TrustchainVCAPI},
//     TrustchainAPI,
// };

use std::net::SocketAddr;

use jsonrpsee::core::client::ClientT;
use jsonrpsee::http_client::HttpClient;
use jsonrpsee::rpc_params;
use jsonrpsee::server::{RpcModule, Server};
use tracing_subscriber::util::SubscriberInitExt;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()?
        .add_directive("jsonrpsee[method_call{name = \"say_hello\"}]=trace".parse()?);
    tracing_subscriber::FmtSubscriber::builder()
        .with_env_filter(filter)
        .finish()
        .try_init()?;

    let (server_addr, handle) = run_server().await?;

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

async fn run_server() -> anyhow::Result<(SocketAddr, jsonrpsee::server::ServerHandle)> {
    let server = Server::builder()
        .build("127.0.0.1:4444".parse::<SocketAddr>()?)
        .await?;
    let mut module = RpcModule::new(());
    module.register_method("say_hello", |_, _, _| "ho")?;

    let addr = server.local_addr()?;
    let handle = server.start(module);

    // Return the server address and handle (to manage shutdown).
    Ok((addr, handle))
}
