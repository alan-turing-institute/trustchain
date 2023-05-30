use crate::errors::TrustchainHTTPError;
use crate::qrcode::str_to_qr_code_html;
use crate::resolver::RootEventTime;
use crate::state::AppState;
use crate::EXAMPLE_VP_REQUEST;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse};
use axum::Json;
use log::info;
use serde::{Deserialize, Serialize};
use ssi::did_resolve::DIDResolver;
use ssi::vc::{Credential, Presentation};
use std::sync::Arc;
use trustchain_ion::verifier::IONVerifier;
use trustchain_ion::IONResolver;

pub struct PresentationRequest;

/// An API for a Trustchain verifier server.
pub trait TrustchainVerifierHTTP {
    /// Constructs a presentation request (given some `presentiation_id`) to send to a credential holder from request wallet by ID
    fn generate_presentation_request(presentation_id: &str) -> PresentationRequest;
    /// Verifies verifiable presentation
    fn verify_presentation(presentation: &Presentation) -> Result<(), TrustchainHTTPError>;
    /// Verifies verifiable credential
    fn verify_credential<T: DIDResolver + Send + Sync>(
        credential: &Credential,
        verifier: &IONVerifier<T>,
    ) -> Result<(), TrustchainHTTPError>;
}

pub struct TrustchainVerifierHTTPHandler;

impl TrustchainVerifierHTTP for TrustchainVerifierHTTPHandler {
    fn generate_presentation_request(presentation_id: &str) -> PresentationRequest {
        todo!()
    }

    fn verify_presentation(presentation: &Presentation) -> Result<(), TrustchainHTTPError> {
        todo!()
    }

    fn verify_credential<T: DIDResolver + Send + Sync>(
        credential: &Credential,
        verifier: &IONVerifier<T>,
    ) -> Result<(), TrustchainHTTPError> {
        // 1. Verify signature on credential is valid given key
        // Use the resolver from the verifier inside:
        //    credential.verify(None, verifier.resolver())
        // 2. Verify did of issuer is valide (same as chain resolution)
        todo!()
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct PostVerifier {
    pub credential: Credential,
    pub root_event_time: RootEventTime,
}

impl TrustchainVerifierHTTPHandler {
    /// API endpoint taking the UUID of a VC. Response is the VC JSON.
    // TODO: identify how to handle multiple string variables
    pub async fn get_verifier() -> Html<String> {
        // Return the presentation request
        // (StatusCode::OK, Json(EXAMPLE_VP_REQUEST))
        Html(EXAMPLE_VP_REQUEST.to_string())
    }

    // pub async fn post_verifier(Json(info): Json<Credential>) -> impl IntoResponse {
    pub async fn post_verifier(
        Json(info): Json<Credential>,
        app_state: Arc<AppState>,
    ) -> impl IntoResponse {
        info!(
            "Received credential at presentation:\n{}",
            serde_json::to_string_pretty(&info).unwrap()
        );

        // TODO: check whether a specific response body is required
        // See [here](https://w3c-ccg.github.io/vc-api/#prove-presentation)
        (StatusCode::OK, "Received!")
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
    // Verifier integration tests
    #[tokio::test]
    #[ignore = "integration test requires ION, MongoDB, IPFS and Bitcoin RPC"]
    async fn test_get_verifier_request() {
        todo!()
    }

    #[tokio::test]
    #[ignore = "integration test requires ION, MongoDB, IPFS and Bitcoin RPC"]
    async fn test_post_verifier_credential() {
        todo!()
    }
}
