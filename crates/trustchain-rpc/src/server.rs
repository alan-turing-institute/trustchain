use jsonrpsee::server::{RpcModule, Server};
use std::{net::SocketAddr, sync::Arc};
use trustchain_api::{api::TrustchainDIDAPI, errors::TrustchainAPIError, TrustchainAPI};
use trustchain_core::verifier::Verifier;

use crate::{config::RPCConfig, state::AppState};

pub async fn run_server(
    config: RPCConfig,
) -> anyhow::Result<(SocketAddr, jsonrpsee::server::ServerHandle)> {
    let server = Server::builder().build(config.to_socket_address()).await?;

    // Set up persistent, shared state.
    let shared_state = Arc::new(AppState::new(config.clone())).clone();
    let root_event_time = config.root_event_time;

    let mut module = RpcModule::new(());

    module.register_async_method("resolve", move |params, _, _| {
        let state = shared_state.clone();
        async move {
            let did = params
                .parse::<String>()
                .map_err(|e| TrustchainAPIError::ParseError(e.to_string()))?;
            tracing::info!("Resolving DID: {:?}", did);
            let resolver = state.verifier.resolver();
            TrustchainAPI::resolve(&did, resolver).await
        }
    })?;

    let shared_state = Arc::new(AppState::new(config.clone())).clone();

    module.register_async_method("verify", move |params, _, _| {
        let state = shared_state.clone();
        async move {
            let did = params
                .parse::<String>()
                .map_err(|e| TrustchainAPIError::ParseError(e.to_string()))?;
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
