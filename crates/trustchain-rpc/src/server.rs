use jsonrpsee::{
    core::RegisterMethodError,
    server::{RpcModule, Server},
};
use serde::{Deserialize, Serialize};
use ssi::{jsonld::ContextLoader, vc::Credential};
use std::{fs::read, net::SocketAddr, sync::Arc};
use trustchain_api::{
    api::{TrustchainDIDAPI, TrustchainDataAPI},
    errors::TrustchainAPIError,
    TrustchainAPI,
};
use trustchain_core::verifier::Verifier;

use crate::{config::RPCConfig, state::AppState};

pub async fn run_server(
    config: RPCConfig,
) -> anyhow::Result<(SocketAddr, jsonrpsee::server::ServerHandle)> {
    let server = Server::builder().build(config.to_socket_address()).await?;

    // Set up persistent, shared state, accessible as context during call execution.
    let shared_state = Arc::new(AppState::new(config.clone())).clone();
    let mut module = RpcModule::new(shared_state);

    module = register_did_methods(module)?;
    module = register_data_methods(module)?;

    let addr = server.local_addr()?;
    let handle = server.start(module);

    // Return the server address and handle (to manage shutdown).
    Ok((addr, handle))
}

fn register_did_methods(
    mut module: RpcModule<Arc<AppState>>,
) -> Result<RpcModule<Arc<AppState>>, RegisterMethodError> {
    module.register_async_method("resolve", |params, ctx, _| async move {
        let did = params
            .parse::<String>()
            .map_err(|e| TrustchainAPIError::ParseError(e.to_string()))?;
        tracing::info!("Resolving DID: {:?}", did);
        let resolver = ctx.verifier.resolver();
        TrustchainAPI::resolve(&did, resolver).await
    })?;

    module.register_async_method("verify", |params, ctx, _| async move {
        let did = params
            .parse::<String>()
            .map_err(|e| TrustchainAPIError::ParseError(e.to_string()))?;
        tracing::info!("Verifying DID: {:?}", did);
        match ctx.config.root_event_time {
            Some(root_event_time) => {
                TrustchainAPI::verify(&did, root_event_time, &ctx.verifier).await
            }
            None => Err(TrustchainAPIError::RootEventTimeNotSet),
        }
    })?;

    module.register_async_method("chain", |params, ctx, _| async move {
        let did = params
            .parse::<String>()
            .map_err(|e| TrustchainAPIError::ParseError(e.to_string()))?;
        tracing::info!("Getting chain for DID: {:?}", did);
        match ctx.config.root_event_time {
            Some(root_event_time) => {
                TrustchainAPI::chain(&did, root_event_time, &ctx.verifier).await
            }
            None => Err(TrustchainAPIError::RootEventTimeNotSet),
        }
    })?;

    module.register_async_method("bundle", |params, ctx, _| async move {
        let did = params
            .parse::<String>()
            .map_err(|e| TrustchainAPIError::ParseError(e.to_string()))?;
        tracing::info!("Getting verification bundle for DID: {:?}", did);
        TrustchainAPI::bundle(&did, &ctx.verifier).await
    })?;

    Ok(module)
}

fn register_data_methods(
    mut module: RpcModule<Arc<AppState>>,
) -> Result<RpcModule<Arc<AppState>>, RegisterMethodError> {
    module.register_async_method("sign_data", |params, ctx, _| async move {
        #[derive(Debug, Deserialize, Serialize)]
        struct SignDataParams {
            path: String,
            did: String,
            key_id: Option<String>,
        }

        let params = params
            .parse::<SignDataParams>()
            .map_err(|e| TrustchainAPIError::ParseError(e.to_string()))?;
        tracing::info!("SignDataParams: {:?}", params);

        // Read the data bytes from the given file path.
        let bytes = read(params.path.clone())
            .map_err(|e| TrustchainAPIError::FileReadError(e.to_string()))?;

        let mut context_loader = ContextLoader::default();
        let result = TrustchainAPI::sign_data(
            &bytes,
            &params.did,
            None,
            params.key_id.as_deref(),
            ctx.verifier.resolver(),
            &mut context_loader,
        )
        .await;
        match result {
            Ok(credential) => {
                tracing::info!("Signed file {}; {} bytes.", params.path, bytes.len());
                return Ok(credential);
            }
            Err(e) => match e {
                // Handle the Key Manager error explicitly (as likely most common).
                TrustchainAPIError::IssuerError(issuer_error) => match issuer_error {
                    trustchain_core::issuer::IssuerError::KeyManager(key_manager_error) => {
                        tracing::warn!(
                            "Failed attempt to sign data. Key not found for DID: {}",
                            &params.did
                        );
                        return Err(TrustchainAPIError::KeyManagerError(key_manager_error));
                    }
                    _ => return Err(TrustchainAPIError::IssuerError(issuer_error)),
                },
                _ => return Err(e),
            },
        }
    })?;

    module.register_async_method("verify_data", |params, ctx, _| async move {
        #[derive(Debug, Deserialize, Serialize)]
        struct VerifyDataParams {
            path: String,
            credential: String,
        }

        let params = params
            .parse::<VerifyDataParams>()
            .map_err(|e| TrustchainAPIError::ParseError(e.to_string()))?;
        tracing::info!("VerifyDataParams: {:?}", params);

        // Read the data bytes from the given file path.
        let bytes = read(params.path.clone())
            .map_err(|e| TrustchainAPIError::FileReadError(e.to_string()))?;

        // Deserialize the credential.
        let credential: Credential = serde_json::from_str(&params.credential)
            .map_err(TrustchainAPIError::FailedToDeserialize)?;

        let mut context_loader = ContextLoader::default();
        match ctx.config.root_event_time {
            Some(root_event_time) => Ok(TrustchainAPI::verify_data(
                &bytes,
                &credential,
                None,
                root_event_time,
                &ctx.verifier,
                &mut context_loader,
            )
            .await?),
            None => return Err(TrustchainAPIError::RootEventTimeNotSet),
        }
    })?;

    Ok(module)
}
