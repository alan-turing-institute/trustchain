use chrono::NaiveDate;
use jsonrpsee::{
    core::RegisterMethodError,
    server::{RpcModule, Server},
};
use serde::{Deserialize, Serialize};
use ssi::{
    jsonld::ContextLoader,
    vc::{Credential, Presentation},
};
use std::{
    fs::{self, read},
    net::SocketAddr,
    sync::Arc,
};
use trustchain_api::{
    api::{
        TrustchainDIDAPI, TrustchainDataAPI, TrustchainRootAPI, TrustchainVCAPI, TrustchainVPAPI,
    },
    errors::TrustchainAPIError,
    TrustchainAPI,
};
use trustchain_core::verifier::Verifier;
use trustchain_ion::root::RootError;

use crate::{config::RPCConfig, state::AppState};

pub async fn run_server(
    config: RPCConfig,
) -> anyhow::Result<(SocketAddr, jsonrpsee::server::ServerHandle)> {
    let server = Server::builder().build(config.to_socket_address()).await?;

    // Set up persistent, shared state, accessible as context during call execution.
    let shared_state = Arc::new(AppState::new(config.clone())).clone();
    let mut module = RpcModule::new(shared_state);

    module = register_did_methods(module)?;
    module = register_vc_methods(module)?;
    module = register_vp_methods(module)?;
    module = register_data_methods(module)?;
    module = register_root_methods(module)?;

    let addr = server.local_addr()?;
    let handle = server.start(module);

    // Return the server address and handle (to manage shutdown).
    Ok((addr, handle))
}

fn register_did_methods(
    mut module: RpcModule<Arc<AppState>>,
) -> Result<RpcModule<Arc<AppState>>, RegisterMethodError> {
    module.register_async_method("create", |params, _, _| async move {
        let path = params
            .parse::<String>()
            .map_err(|e| TrustchainAPIError::ParseError(e.to_string()))?;

        // Read the document state from the given file path.
        let doc_state = match fs::File::open(path.clone()) {
            Ok(file) => serde_json::from_reader(file)?,
            Err(e) => return Err(TrustchainAPIError::FileReadError(e.to_string())),
        };
        tracing::info!("Creating DID from doc state at: {}", path);
        TrustchainAPI::create(doc_state, false)
    })?;

    module.register_async_method("attest", |params, _, _| async move {
        #[derive(Debug, Deserialize, Serialize)]
        struct AttestParams {
            did: String,
            controlled_did: String,
        }
        let params = params
            .parse::<AttestParams>()
            .map_err(|e| TrustchainAPIError::ParseError(e.to_string()))?;
        tracing::info!("Handling dDID attest request: {:?}", params);

        TrustchainAPI::attest(&params.did, &params.controlled_did, false).await
    })?;

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

fn register_vc_methods(
    mut module: RpcModule<Arc<AppState>>,
) -> Result<RpcModule<Arc<AppState>>, RegisterMethodError> {
    module.register_async_method("sign_credential", |params, ctx, _| async move {
        #[derive(Debug, Deserialize, Serialize)]
        struct SignCredentialParams {
            credential: String,
            did: String,
            key_id: Option<String>,
        }
        let params = params
            .parse::<SignCredentialParams>()
            .map_err(|e| TrustchainAPIError::ParseError(e.to_string()))?;
        tracing::info!("Handling sign VC request: {:?}", params);

        // Deserialize the credential.
        let credential = serde_json::from_str(&params.credential)
            .map_err(TrustchainAPIError::FailedToDeserialize)?;

        let mut context_loader = ContextLoader::default();
        let result = TrustchainAPI::sign(
            credential,
            &params.did,
            None,
            params.key_id.as_deref(),
            ctx.verifier.resolver(),
            &mut context_loader,
        )
        .await;
        match result {
            Ok(credential) => {
                tracing::info!("Signed credential.");
                return Ok(credential);
            }
            Err(e) => Err(handle_failed_sign_attempt(e, &params.did)),
        }
    })?;

    module.register_async_method("verify_credential", |params, ctx, _| async move {
        let credential_str = params
            .parse::<String>()
            .map_err(|e| TrustchainAPIError::ParseError(e.to_string()))?;

        // Deserialize the credential.
        let credential: Credential = serde_json::from_str(&credential_str)
            .map_err(TrustchainAPIError::FailedToDeserialize)?;

        tracing::info!("Verifying credential.");
        let mut context_loader = ContextLoader::default();
        match ctx.config.root_event_time {
            Some(root_event_time) => Ok(TrustchainAPI::verify_credential(
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

fn register_vp_methods(
    mut module: RpcModule<Arc<AppState>>,
) -> Result<RpcModule<Arc<AppState>>, RegisterMethodError> {
    module.register_async_method("sign_presentation", |params, ctx, _| async move {
        #[derive(Debug, Deserialize, Serialize)]
        struct SignPresentationParams {
            presentation: String,
            did: String,
            key_id: Option<String>,
        }
        let params = params
            .parse::<SignPresentationParams>()
            .map_err(|e| TrustchainAPIError::ParseError(e.to_string()))?;
        tracing::info!("Handling sign VP request: {:?}", params);

        // Deserialize the credential.
        let presentation = serde_json::from_str(&params.presentation)
            .map_err(TrustchainAPIError::FailedToDeserialize)?;

        let mut context_loader = ContextLoader::default();
        let result = TrustchainAPI::sign_presentation(
            presentation,
            &params.did,
            None,
            params.key_id.as_deref(),
            ctx.verifier.resolver(),
            &mut context_loader,
        )
        .await;
        match result {
            Ok(presentation) => {
                tracing::info!("Signed presentation.");
                return Ok(presentation);
            }
            Err(e) => Err(handle_failed_sign_attempt(e, &params.did)),
        }
    })?;

    module.register_async_method("verify_presentation", |params, ctx, _| async move {
        let presentation_str = params
            .parse::<String>()
            .map_err(|e| TrustchainAPIError::ParseError(e.to_string()))?;

        // Deserialize the presentation.
        let presentation: Presentation = serde_json::from_str(&presentation_str)
            .map_err(TrustchainAPIError::FailedToDeserialize)?;

        tracing::info!("Verifying credential.");
        let mut context_loader = ContextLoader::default();
        match ctx.config.root_event_time {
            Some(root_event_time) => Ok(TrustchainAPI::verify_presentation(
                &presentation,
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
        tracing::info!("Handling sign data request: {:?}", params);

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
            Err(e) => Err(handle_failed_sign_attempt(e, &params.did)),
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
        tracing::info!("Handling verify data request: {:?}", params);

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

fn handle_failed_sign_attempt(err: TrustchainAPIError, did: &str) -> TrustchainAPIError {
    match err {
        // Handle the Key Manager error explicitly (as likely most common).
        TrustchainAPIError::IssuerError(issuer_error) => match issuer_error {
            trustchain_core::issuer::IssuerError::KeyManager(key_manager_error) => {
                tracing::warn!(
                    "Failed attempt to sign data. Key not found for DID: {}",
                    did
                );
                return TrustchainAPIError::KeyManagerError(key_manager_error);
            }
            _ => return TrustchainAPIError::IssuerError(issuer_error),
        },
        _ => return err,
    }
}

fn register_root_methods(
    mut module: RpcModule<Arc<AppState>>,
) -> Result<RpcModule<Arc<AppState>>, RegisterMethodError> {
    module.register_async_method("root_candidates", |params, ctx, _| async move {
        #[derive(Debug, Deserialize, Serialize)]
        struct RootCandidatesParams {
            year: i32,
            month: u32,
            day: u32,
        }
        let params = params
            .parse::<RootCandidatesParams>()
            .map_err(|e| TrustchainAPIError::ParseError(e.to_string()))?;
        tracing::info!("Handling root candidates request: {:?}", params);

        let date = match NaiveDate::from_ymd_opt(params.year, params.month, params.day) {
            Some(d) => d,
            None => {
                return Err(RootError::InvalidDate(params.year, params.month, params.day).into())
            }
        };
        TrustchainAPI::root_candidates(date, Some(&ctx.root_candidates)).await
    })?;

    module.register_async_method("block_timestamp", |params, _, _| async move {
        let height = params
            .parse::<u64>()
            .map_err(|e| TrustchainAPIError::ParseError(e.to_string()))?;
        tracing::info!("Getting timestamp for block height: {}", height);

        TrustchainAPI::block_timestamp(height).await
    })?;

    Ok(module)
}
