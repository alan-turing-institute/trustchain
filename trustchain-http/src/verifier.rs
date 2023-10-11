use crate::config::http_config;
use crate::errors::TrustchainHTTPError;
use crate::qrcode::{str_to_qr_code_html, DIDQRCode};
use crate::state::AppState;
use async_trait::async_trait;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse};
use axum::Json;
use log::info;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use ssi::did_resolve::DIDResolver;
use ssi::jsonld::ContextLoader;
use ssi::ldp::LinkedDataDocument;
use ssi::vc::{Credential, Presentation};
use std::sync::Arc;
use trustchain_api::api::TrustchainVPAPI;
use trustchain_api::TrustchainAPI;
use trustchain_core::verifier::{Timestamp, Verifier};
use trustchain_ion::verifier::IONVerifier;

/// A type for presentation requests. See [VP request spec](https://w3c-ccg.github.io/vp-request-spec/)
/// for further details.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct PresentationRequest(Value);

/// An API for a Trustchain verifier server.
#[async_trait]
pub trait TrustchainVerifierHTTP {
    /// Verifies verifiable presentation.
    async fn verify_presentation<T: DIDResolver + Send + Sync>(
        presentation: &Presentation,
        root_event_time: Timestamp,
        verifier: &IONVerifier<T>,
    ) -> Result<(), TrustchainHTTPError> {
        Ok(TrustchainAPI::verify_presentation(
            presentation,
            None,
            root_event_time,
            verifier,
            // TODO [#128]: move into API upon context loader added to app_state
            &mut ContextLoader::default(),
        )
        .await?)
    }
    /// Verifies verifiable credential.
    async fn verify_credential<T: DIDResolver + Send + Sync>(
        credential: &Credential,
        root_event_time: Timestamp,
        verifier: &IONVerifier<T>,
    ) -> Result<(), TrustchainHTTPError> {
        let verify_credential_result = credential
            .verify(None, verifier.resolver(), &mut ContextLoader::default())
            .await;
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

/// Struct for deserializing credential and corresponding root event time.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PostVerifier {
    pub presentation_or_credential: PresentationOrCredential,
    // TODO [#130]: update field upon root event time changing to date and confirmation code.
    pub root_event_time: Timestamp,
}

/// Enum for indicating whether verification information is a presentation or credential.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PresentationOrCredential {
    Presentation(Presentation),
    Credential(Credential),
}

impl TrustchainVerifierHTTPHandler {
    /// API endpoint taking the UUID of a presentation request.
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
    /// Handler for presentation or credential received from POST.
    pub async fn post_verifier(
        Json(verification_info): Json<PostVerifier>,
        app_state: Arc<AppState>,
    ) -> impl IntoResponse {
        let verification_info_json = serde_json::to_string_pretty(&verification_info)
            .map_err(TrustchainHTTPError::FailedToDeserialize)?;
        info!("Received verification information:\n{verification_info_json}",);

        match verification_info.presentation_or_credential {
            PresentationOrCredential::Presentation(ref presentation) => {
                TrustchainVerifierHTTPHandler::verify_presentation(
                    presentation,
                    app_state
                        .config
                        .root_event_time
                        .ok_or(TrustchainHTTPError::RootEventTimeNotSet)?,
                    &app_state.verifier,
                )
                .await
                .map(|_| {
                    info!("Presentation verification...ok ✅:\n{verification_info_json}");
                    (StatusCode::OK, Html("Presentation received and verified!"))
                })
                .map_err(|err| {
                    info!("Presentation verification...error ❌:\n{err}");
                    err
                })
            }
            PresentationOrCredential::Credential(ref credential) => {
                TrustchainVerifierHTTPHandler::verify_credential(
                    credential,
                    app_state
                        .config
                        .root_event_time
                        .ok_or(TrustchainHTTPError::RootEventTimeNotSet)?,
                    &app_state.verifier,
                )
                .await
                .map(|_| {
                    info!("Credential verification...ok ✅:\n{verification_info_json}");
                    (StatusCode::OK, Html("Credential received and verified!"))
                })
                .map_err(|err| {
                    info!("Credential verification...error ❌:\n{err}");
                    err
                })
            }
        }
    }

    /// Generates a QR code for receiving requests, default to first request in cache
    pub async fn get_verifier_qrcode(State(app_state): State<Arc<AppState>>) -> impl IntoResponse {
        app_state
            .presentation_requests
            .iter()
            .next()
            .ok_or(TrustchainHTTPError::RequestDoesNotExist)
            .map(|(uid, _)| {
                let qr_code_str = if http_config().verifiable_endpoints.unwrap_or(true) {
                    serde_json::to_string(&DIDQRCode {
                        did: app_state.config.server_did.as_ref().unwrap().to_owned(),
                        route: "/vc/verifier/".to_string(),
                        uuid: uid.to_owned(),
                    })
                    .unwrap()
                } else {
                    format!(
                        "{}://{}:{}/vc/verifier/{uid}",
                        http_config().http_scheme(),
                        app_state.config.host_display,
                        app_state.config.port
                    )
                };
                (
                    StatusCode::OK,
                    Html(str_to_qr_code_html(&qr_code_str, "Verifier")),
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
    use std::{collections::HashMap, sync::Arc};

    lazy_static! {
        /// Lazy static reference to core configuration loaded from `trustchain_config.toml`.
        pub static ref TEST_HTTP_CONFIG: HTTPConfig = HTTPConfig {
            server_did: Some("did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q".to_string()),
            root_event_time: Some(1666265405),
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

    const TEST_POST_VERIFIER_CREDENTIAL: &str = r#"
    {
        "presentationOrCredential": {
          "credential": {
            "@context": [
              "https://www.w3.org/2018/credentials/v1",
              "https://www.w3.org/2018/credentials/examples/v1"
            ],
            "id": "urn:uuid:46cb84e2-fa10-11ed-a0d4-bbb4e61d1556",
            "type": ["VerifiableCredential"],
            "credentialSubject": {
              "id": "did:example:284b3f34fad911ed9aea439566dd422a",
              "familyName": "Bloggs",
              "degree": {
                "college": "University of Oxbridge",
                "name": "Bachelor of Arts",
                "type": "BachelorDegree"
              },
              "givenName": "Jane"
            },
            "issuer": "did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q",
            "issuanceDate": "2023-08-08T08:59:21.458576Z",
            "proof": {
              "type": "EcdsaSecp256k1Signature2019",
              "proofPurpose": "assertionMethod",
              "verificationMethod": "did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q#ePyXsaNza8buW6gNXaoGZ07LMTxgLC9K7cbaIjIizTI",
              "created": "2023-08-08T08:59:21.461Z",
              "jws": "eyJhbGciOiJFUzI1NksiLCJjcml0IjpbImI2NCJdLCJiNjQiOmZhbHNlfQ..LqLHztj2djQ9aWDGFjm3ZaOzDFIVKnOyZQVvE7CMDbYV5POYz6IejwnRkcqRf7uPYc2QbJAqCjj20PfwTOPJEw"
            }
          }
        },
        "rootEventTime": 1666265405
    }
    "#;

    const TEST_POST_VERIFIER_PRESENTATION: &str = r#"
    {
        "presentationOrCredential": {
          "presentation": {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": "VerifiablePresentation",
            "verifiableCredential": [
              {
                "@context": [
                  "https://www.w3.org/2018/credentials/v1",
                  "https://www.w3.org/2018/credentials/examples/v1",
                  "https://w3id.org/citizenship/v1"
                ],
                "type": ["VerifiableCredential"],
                "credentialSubject": {
                  "familyName": "Doe",
                  "givenName": "Jane",
                  "degree": {
                    "type": "BachelorDegree",
                    "name": "Bachelor of Science and Arts",
                    "college": "College of Engineering"
                  }
                },
                "issuer": "did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q",
                "issuanceDate": "2023-09-06T12:15:08.630033Z",
                "proof": {
                  "type": "EcdsaSecp256k1Signature2019",
                  "proofPurpose": "assertionMethod",
                  "verificationMethod": "did:ion:test:EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A#kjqrr3CTkmlzJZVo0uukxNs8vrK5OEsk_OcoBO4SeMQ",
                  "created": "2023-09-08T07:50:31.529Z",
                  "jws": "eyJhbGciOiJFUzI1NksiLCJjcml0IjpbImI2NCJdLCJiNjQiOmZhbHNlfQ..AOodNoJ20UJtVK1UFsMXxr2kVpurIGjLCvTmwZKs_ahVO9GWPH05ZpM14VLanCK33K0AR6mlSna5y7DwfojDEw"
                },
                "credentialSchema": {
                  "id": "did:example:cdf:35LB7w9ueWbagPL94T9bMLtyXDj9pX5o",
                  "type": "did:example:schema:22KpkXgecryx9k7N6XN1QoN3gXwBkSU8SfyyYQG"
                },
                "image": "some_base64_representation"
              }
            ],
            "proof": {
              "type": "EcdsaSecp256k1Signature2019",
              "proofPurpose": "authentication",
              "verificationMethod": "did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q#ePyXsaNza8buW6gNXaoGZ07LMTxgLC9K7cbaIjIizTI",
              "created": "2023-09-08T07:50:31.619Z",
              "jws": "eyJhbGciOiJFUzI1NksiLCJjcml0IjpbImI2NCJdLCJiNjQiOmZhbHNlfQ..tXGzMYY9jdyK_fy-h99XbmUNM-V3LOtNgP_0LfhVPHBHH57TKzqAv7AWPUl4Jhqvc1L3RrvJcdwyHnZnubccvg"
            },
            "holder": "did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q"
          }
        },
        "rootEventTime": 1666265405
    }
    "#;

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

    #[tokio::test]
    #[ignore = "integration test requires ION, MongoDB, IPFS and Bitcoin RPC"]
    async fn test_post_verifier_credential() {
        let state = Arc::new(AppState::new_with_cache(
            TEST_HTTP_CONFIG.to_owned(),
            HashMap::new(),
            serde_json::from_str(REQUESTS).unwrap(),
        ));
        // Test post of credential to verifier
        let app = TrustchainRouter::from(state.clone()).into_router();
        let uid = "b9519df2-35c1-11ee-8314-7f66e4585b4f";
        let uri = format!("/vc/verifier/{uid}");
        let client = TestClient::new(app);
        let post_verifier: PostVerifier =
            serde_json::from_str(TEST_POST_VERIFIER_CREDENTIAL).unwrap();
        let response = client.post(&uri).json(&post_verifier).send().await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!("Credential received and verified!", response.text().await);
    }

    #[tokio::test]
    #[ignore = "integration test requires ION, MongoDB, IPFS and Bitcoin RPC"]
    async fn test_post_verifier_presentation() {
        let state = Arc::new(AppState::new_with_cache(
            TEST_HTTP_CONFIG.to_owned(),
            HashMap::new(),
            serde_json::from_str(REQUESTS).unwrap(),
        ));
        // Test post of presentation to verifier
        let app = TrustchainRouter::from(state.clone()).into_router();
        let uid = "b9519df2-35c1-11ee-8314-7f66e4585b4f";
        let uri = format!("/vc/verifier/{uid}");
        let client = TestClient::new(app);
        let post_verifier: PostVerifier =
            serde_json::from_str(TEST_POST_VERIFIER_PRESENTATION).unwrap();
        let response = client.post(&uri).json(&post_verifier).send().await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!("Presentation received and verified!", response.text().await);
    }
}
