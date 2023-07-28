use crate::errors::TrustchainHTTPError;
use crate::qrcode::str_to_qr_code_html;
use crate::resolver::RootEventTime;
use crate::state::AppState;
use crate::EXAMPLE_VP_REQUEST;
use async_trait::async_trait;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse};
use axum::Json;
use log::info;
use serde::{Deserialize, Serialize};
use ssi::did_resolve::DIDResolver;
use ssi::vc::{Credential, Issuer, Presentation, URI};
use std::sync::Arc;
use trustchain_core::verifier::{Timestamp, Verifier};
use trustchain_ion::verifier::IONVerifier;

pub struct PresentationRequest;

/// An API for a Trustchain verifier server.
#[async_trait]
pub trait TrustchainVerifierHTTP {
    /// Constructs a presentation request (given some `presentiation_id`) to send to a credential holder from request wallet by ID
    fn generate_presentation_request(presentation_id: &str) -> PresentationRequest {
        todo!()
    }
    /// Verifies verifiable presentation
    async fn verify_presentation(presentation: &Presentation) -> Result<(), TrustchainHTTPError> {
        todo!()
    }
    /// Verifies verifiable credential
    async fn verify_credential<T: DIDResolver + Send + Sync>(
        credential: &Credential,
        root_event_time: Timestamp,
        verifier: &IONVerifier<T>,
    ) -> Result<(), TrustchainHTTPError> {
        let verify_credential_result = credential.verify(None, verifier.resolver()).await;
        if !verify_credential_result.errors.is_empty() {
            return Err(TrustchainHTTPError::InvalidSignature);
        }
        match credential.issuer {
            Some(Issuer::URI(URI::String(ref issuer))) => {
                Ok(verifier.verify(issuer, root_event_time).await.map(|_| ())?)
            }
            _ => Err(TrustchainHTTPError::NoCredentialIssuer),
        }
    }
}

/// TODO
pub struct TrustchainVerifierHTTPHandler;

impl TrustchainVerifierHTTP for TrustchainVerifierHTTPHandler {}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// Struct for deserializing credential and corresponding root event time.
pub struct PostVerifier {
    pub credential: Credential,
    pub root_event_time: Timestamp,
}

impl TrustchainVerifierHTTPHandler {
    /// API endpoint taking the UUID of a VC. Response is the VC JSON.
    // TODO: refine to allow a specific ID for the request to be passed and extracted from path
    pub async fn get_verifier() -> impl IntoResponse {
        (StatusCode::OK, Json(EXAMPLE_VP_REQUEST))
    }
    /// Handler for credential received from POST.
    pub async fn post_verifier(
        Json(verification_info): Json<PostVerifier>,
        app_state: Arc<AppState>,
    ) -> impl IntoResponse {
        info!(
            "Received credential at presentation:\n{}",
            serde_json::to_string_pretty(&verification_info).unwrap()
        );

        TrustchainVerifierHTTPHandler::verify_credential(
            &verification_info.credential,
            verification_info.root_event_time,
            &app_state.verifier,
        )
        .await
        .map(|_| {
            (
                StatusCode::CREATED,
                Html("Presentation successfully proved!"),
            )
        })
    }

    pub async fn get_verifier_qrcode(State(app_state): State<Arc<AppState>>) -> Html<String> {
        // Generate a QR code for server address and combination of name and UUID
        let address_str = format!(
            "http://{}:{}/vc/verifier",
            app_state.config.host_reference, app_state.config.port
        );

        // Respond with the QR code as a png embedded in html
        Html(str_to_qr_code_html(&address_str, "Verifier"))
    }
}

#[cfg(test)]
mod tests {
    // TODO: complete tests as part of verifier completion (#56)
    // // Verifier integration tests
    // #[tokio::test]
    // #[ignore = "integration test requires ION, MongoDB, IPFS and Bitcoin RPC"]
    // async fn test_get_verifier_request() {
    //     todo!()
    // }

    // #[tokio::test]
    // #[ignore = "integration test requires ION, MongoDB, IPFS and Bitcoin RPC"]
    // async fn test_post_verifier_credential() {
    //     todo!()
    // }
}
