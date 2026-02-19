use jsonrpsee::server::{RpcModule, Server};
use std::{net::SocketAddr, sync::Arc};
use trustchain_api::{TrustchainAPI, api::TrustchainDIDAPI, errors::TrustchainAPIError};
use trustchain_core::verifier::Verifier;

use crate::{config::RPCConfig, state::AppState};

pub async fn run_server(
    config: RPCConfig,
) -> anyhow::Result<(SocketAddr, jsonrpsee::server::ServerHandle)> {
    // TODO: use config for host & port.
    let server = Server::builder()
        .build("127.0.0.1:4444".parse::<SocketAddr>()?)
        .await?;

    // Set up persistent, shared state.
    let root_event_time = config.root_event_time;
    let shared_state = Arc::new(AppState::new(config.clone())).clone();

    let mut module = RpcModule::new(());

    // TEMP EXAMPLES:
    module.register_method("say_hello", |_, _, _| "ho")?;
    module.register_method("say_params", |params, _, _| params.parse::<String>())?;

    module.register_async_method("resolve", move |params, _, _| {
        let state = shared_state.clone();
        async move {
            // TODO: fix the unwrap here:
            let did = params.parse::<String>().unwrap();
            tracing::info!("Resolving DID: {:?}", did);
            let resolver = state.verifier.resolver();
            TrustchainAPI::resolve(&did, resolver).await
        }
    })?;

    let shared_state = Arc::new(AppState::new(config.clone())).clone();

    module.register_async_method("verify", move |params, _, _| {
        let state = shared_state.clone();
        async move {
            // TODO: fix the unwrap here:
            let did = params.parse::<String>().unwrap();
            tracing::info!("Verifying DID: {:?}", did);
            match root_event_time {
                Some(time) => TrustchainAPI::verify(&did, time, &state.verifier).await,
                None => Err(TrustchainAPIError::RootEventTimeNotSet),
            }
        }
    })?;

    let addr = server.local_addr()?;
    let handle = server.start(module);

    // Return the server address and handle (to manage shutdown).
    Ok((addr, handle))
}
