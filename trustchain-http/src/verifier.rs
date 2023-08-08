use crate::errors::TrustchainHTTPError;
use crate::qrcode::str_to_qr_code_html;
use crate::resolver::RootEventTime;
use crate::state::AppState;
use crate::EXAMPLE_VP_REQUEST;
use async_trait::async_trait;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse};
use axum::Json;
use log::info;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use ssi::did_resolve::DIDResolver;
use ssi::ldp::LinkedDataDocument;
use ssi::vc::{Credential, Presentation, URI};
use std::sync::Arc;
use trustchain_core::verifier::{Timestamp, Verifier};
use trustchain_ion::verifier::IONVerifier;

/// A type for presentation requests. See [VP request spec](https://w3c-ccg.github.io/vp-request-spec/)
/// for further details.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct PresentationRequest(Value);

/// An API for a Trustchain verifier server.
#[async_trait]
pub trait TrustchainVerifierHTTP {
    /// Constructs a presentation request (given some `presentiation_id`) to send to a credential
    /// holder from request wallet by ID.
    fn generate_presentation_request(_presentation_id: &str) -> PresentationRequest {
        todo!()
    }
    /// Verifies verifiable presentation.
    async fn verify_presentation(_presentation: &Presentation) -> Result<(), TrustchainHTTPError> {
        todo!()
    }
    /// Verifies verifiable credential.
    async fn verify_credential<T: DIDResolver + Send + Sync>(
        credential: &Credential,
        root_event_time: Timestamp,
        verifier: &IONVerifier<T>,
    ) -> Result<(), TrustchainHTTPError> {
        let verify_credential_result = credential.verify(None, verifier.resolver()).await;
        if !verify_credential_result.errors.is_empty() {
            return Err(TrustchainHTTPError::InvalidSignature);
        }
        match credential.get_issuer() {
            Some(issuer) => Ok(verifier.verify(issuer, root_event_time).await.map(|_| ())?),
            _ => Err(TrustchainHTTPError::NoCredentialIssuer),
        }
    }
}

/// Handler for verification of credentials and presentations.
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
    pub async fn get_verifier(
        Path(request_id): Path<String>,
        State(app_state): State<Arc<AppState>>,
    ) -> impl IntoResponse {
        app_state
            .presentation_requests
            .get(&request_id)
            .ok_or(TrustchainHTTPError::RequestDoesNotExist)
            .map(|request| (StatusCode::OK, Json(request.to_owned())))
    }
    /// Handler for credential received from POST.
    pub async fn post_verifier(
        Json(verification_info): Json<PostVerifier>,
        app_state: Arc<AppState>,
    ) -> impl IntoResponse {
        info!(
            "Received credential:\n{}",
            serde_json::to_string_pretty(&verification_info)
                .map_err(TrustchainHTTPError::FailedToDeserialize)?
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
    /// Generates a QR code for receiving requests, default to first request in cache
    pub async fn get_verifier_qrcode(State(app_state): State<Arc<AppState>>) -> impl IntoResponse {
        app_state
            .presentation_requests
            .iter()
            .next()
            .ok_or(TrustchainHTTPError::RequestDoesNotExist)
            .map(|(uid, _)| {
                let address_str = format!(
                    "http://{}:{}/vc/verifier/{}",
                    app_state.config.host_reference, app_state.config.port, uid
                );
                (
                    StatusCode::OK,
                    Html(str_to_qr_code_html(&address_str, "Verifier")),
                )
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::HTTPConfig, errors::TrustchainHTTPError, server::TrustchainRouter, state::AppState,
    };
    use axum_test_helper::TestClient;
    use hyper::StatusCode;
    use lazy_static::lazy_static;
    use serde_json::json;
    use ssi::{
        one_or_many::OneOrMany,
        vc::{Credential, CredentialSubject, Issuer, URI},
    };
    use std::{collections::HashMap, sync::Arc};
    use trustchain_core::{utils::canonicalize, verifier::Verifier};
    use trustchain_ion::{get_ion_resolver, verifier::IONVerifier};

    lazy_static! {
        /// Lazy static reference to core configuration loaded from `trustchain_config.toml`.
        pub static ref TEST_HTTP_CONFIG: HTTPConfig = HTTPConfig {
            issuer_did: Some("did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q".to_string()),
            ..Default::default()
        };
    }

    const REQUESTS: &str = r#"
    {
        "b9519df2-35c1-11ee-8314-7f66e4585b4f": {
            "type": "VerifiablePresentationRequest",
            "query": [
                {
                    "type": "QueryByExample",
                    "credentialQuery": {
                        "reason": "Request credential",
                        "example": {
                            "@context": [
                                "https://www.w3.org/2018/credentials/v1"
                            ],
                            "type": "VerifiableCredential"
                        }
                    }
                }
            ],
            "challenge": "a877fb0a-11dd-11ee-9df7-9be7abdeee2d",
            "domain": "https://alan-turing-institute.github.io/trustchain"
        }
    }
    "#;
    // TODO: complete tests as part of verifier completion (#56)
    // Verifier integration tests
    #[tokio::test]
    #[ignore = "integration test requires ION, MongoDB, IPFS and Bitcoin RPC"]
    async fn test_get_verifier_request() {
        let state = Arc::new(AppState::new_with_cache(
            TEST_HTTP_CONFIG.to_owned(),
            HashMap::new(),
            serde_json::from_str(REQUESTS).unwrap(),
        ));
        // Test response for request in cache
        let app = TrustchainRouter::from(state.clone()).into_router();
        let uid = "b9519df2-35c1-11ee-8314-7f66e4585b4f";
        let uri = format!("/vc/verifier/{uid}");
        let client = TestClient::new(app);
        let response = client.get(&uri).send().await;

        // Test response is OK
        assert_eq!(response.status(), StatusCode::OK);

        // Test response json same as cache
        let expected_request = state.presentation_requests.get(uid).unwrap();
        let actual_request = response.json::<PresentationRequest>().await;
        assert_eq!(&actual_request, expected_request);

        // Test response for non-existent request
        let app = TrustchainRouter::from(state.clone()).into_router();
        let uid = "dd2f6d68-35c5-11ee-98c7-d317dc01648b";
        let uri = format!("/vc/verifier/{uid}");
        let client = TestClient::new(app);
        let response = client.get(&uri).send().await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response.text().await,
            json!({"error":TrustchainHTTPError::RequestDoesNotExist.to_string()}).to_string()
        );
    }

    // #[tokio::test]
    // #[ignore = "integration test requires ION, MongoDB, IPFS and Bitcoin RPC"]
    // async fn test_post_verifier_credential() {
    //     todo!()
    // }
}
