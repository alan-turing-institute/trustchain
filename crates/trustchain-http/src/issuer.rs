//! Handlers and trait for issuing VCs and providing credential offers.
use crate::config::http_config;
use crate::errors::TrustchainHTTPError;
use crate::qrcode::{str_to_qr_code_html, DIDQRCode};
use crate::state::AppState;
use crate::store::CredentialStoreItem;
use async_trait::async_trait;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse};
use axum::Json;
use chrono::Utc;
use log::info;
use serde::{Deserialize, Serialize};
use ssi::jsonld::ContextLoader;
use ssi::jwk::Algorithm;
use ssi::one_or_many::OneOrMany;
use ssi::vc::Credential;
use ssi::vc::VCDateTime;
use std::sync::Arc;
use trustchain_core::issuer::Issuer;
use trustchain_core::resolver::TrustchainResolver;
use trustchain_core::verifier::Verifier;
use trustchain_ion::attestor::IONAttestor;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
/// Data type for a credential offer.
pub struct CredentialOffer {
    pub type_: Option<String>,
    pub credential_preview: Credential,
    pub expires: Option<VCDateTime>,
}

impl CredentialOffer {
    pub fn new(credential: Credential) -> Self {
        CredentialOffer {
            type_: Some("CredentialOffer".to_string()),
            credential_preview: credential,
            // Offer is 60 mins after now
            expires: Some(VCDateTime::from(Utc::now() + chrono::Duration::minutes(60))),
        }
    }
    /// Generates credential offer adding the UUID to the credential
    pub fn generate(credential: &Credential, id: &str) -> Self {
        let mut credential: Credential = credential.to_owned();
        credential.id = Some(ssi::vc::StringOrURI::URI(ssi::vc::URI::String(format!(
            "urn:uuid:{}",
            id
        ))));
        Self::new(credential)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
/// Type for deserializing information provided by holder in issuing POST request.
pub struct VcInfo {
    subject_id: String,
}

/// An API for a Trustchain verifier server.
#[async_trait]
pub trait TrustchainIssuerHTTP {
    /// Issues an offer for a verifiable credential
    fn generate_credential_offer(template: &CredentialStoreItem, id: &str) -> CredentialOffer;
    /// Issues a verifiable credential.
    async fn issue_credential(
        credential_store_item: &CredentialStoreItem,
        subject_id: Option<&str>,
        resolver: &dyn TrustchainResolver,
        rss: bool,
    ) -> Result<Credential, TrustchainHTTPError>;
}

/// Type for implementing the TrustchainIssuerHTTP trait that will contain additional handler methods.
pub struct TrustchainIssuerHTTPHandler;

#[async_trait]
impl TrustchainIssuerHTTP for TrustchainIssuerHTTPHandler {
    fn generate_credential_offer(template: &CredentialStoreItem, id: &str) -> CredentialOffer {
        let mut credential = template.credential.to_owned();
        credential.issuer = Some(ssi::vc::Issuer::URI(ssi::vc::URI::String(
            template.issuer_did.to_string(),
        )));
        CredentialOffer::generate(&credential, id)
    }

    async fn issue_credential(
        credential_store_item: &CredentialStoreItem,
        subject_id: Option<&str>,
        resolver: &dyn TrustchainResolver,
        rss: bool,
    ) -> Result<Credential, TrustchainHTTPError> {
        let mut credential = credential_store_item.credential.to_owned();
        credential.issuer = Some(ssi::vc::Issuer::URI(ssi::vc::URI::String(
            credential_store_item.issuer_did.to_string(),
        )));
        let now = chrono::offset::Utc::now();
        credential.issuance_date = Some(VCDateTime::from(now));
        if let Some(subject_id_str) = subject_id {
            if let OneOrMany::One(ref mut subject) = credential.credential_subject {
                subject.id = Some(ssi::vc::URI::String(subject_id_str.to_string()));
            }
        }

        let issuer = IONAttestor::new(&credential_store_item.issuer_did);
        let key_id = if rss {
            // TODO: move key management filtering logic into AttestorKeyManager.
            let signing_keys = issuer.signing_keys()?;
            signing_keys
                .into_iter()
                .filter(|key| matches!(key.get_algorithm(), Some(Algorithm::RSS2023)))
                .map(|jwk| jwk.thumbprint())
                .take(1)
                .collect::<Result<String, _>>()
                .ok()
        } else {
            None
        };

        Ok(issuer
            .sign(
                &credential,
                None,
                key_id.as_deref(),
                resolver,
                // TODO: add context loader to app_state
                &mut ContextLoader::default(),
            )
            .await?)
    }
}

impl TrustchainIssuerHTTPHandler {
    /// Generates QR code to display to holder to receive requested credential.
    pub async fn get_issuer_qrcode(
        State(app_state): State<Arc<AppState>>,
        Path(id): Path<String>,
    ) -> Result<Html<String>, TrustchainHTTPError> {
        let did = app_state
            .credentials
            .get(&id)
            .ok_or(TrustchainHTTPError::CredentialDoesNotExist)?
            .issuer_did
            .to_owned();
        let qr_code_str = if http_config().verifiable_endpoints.unwrap_or(true) {
            serde_json::to_string(&DIDQRCode {
                did,
                service: "TrustchainHTTP".to_string(),
                relative_ref: Some(format!("/vc/issuer/{id}")),
            })
            .unwrap()
        } else {
            format!(
                "{}://{}:{}/vc/issuer/{id}",
                http_config().http_scheme(),
                app_state.config.host_display,
                app_state.config.port
            )
        };
        // Respond with the QR code as a png embedded in html
        Ok(Html(str_to_qr_code_html(&qr_code_str, "Issuer")))
    }

    pub async fn get_issuer_qrcode_rss(
        State(app_state): State<Arc<AppState>>,
        Path(id): Path<String>,
    ) -> Result<Html<String>, TrustchainHTTPError> {
        let did = app_state
            .credentials
            .get(&id)
            .ok_or(TrustchainHTTPError::CredentialDoesNotExist)?
            .issuer_did
            .to_owned();
        let qr_code_str = if http_config().verifiable_endpoints.unwrap_or(true) {
            serde_json::to_string(&DIDQRCode {
                did,
                service: "TrustchainHTTP".to_string(),
                relative_ref: Some(format!("/vc_rss/issuer/{id}")),
            })
            .unwrap()
        } else {
            format!(
                "{}://{}:{}/vc_rss/issuer/{id}",
                http_config().http_scheme(),
                app_state.config.host_display,
                app_state.config.port
            )
        };
        // Respond with the QR code as a png embedded in html
        Ok(Html(str_to_qr_code_html(&qr_code_str, "Issuer")))
    }

    /// API endpoint taking the UUID of a VC. Response is the VC JSON.
    pub async fn get_issuer(
        Path(credential_id): Path<String>,
        State(app_state): State<Arc<AppState>>,
    ) -> impl IntoResponse {
        app_state
            .credentials
            .get(&credential_id)
            .ok_or(TrustchainHTTPError::CredentialDoesNotExist)
            .map(|credential_store_item| {
                (
                    StatusCode::OK,
                    Json(TrustchainIssuerHTTPHandler::generate_credential_offer(
                        credential_store_item,
                        &credential_id,
                    )),
                )
            })
    }
    /// Receives subject DID in response to offer and returns signed credential.
    pub async fn post_issuer(
        (Path(credential_id), Json(vc_info)): (Path<String>, Json<VcInfo>),
        app_state: Arc<AppState>,
        rss: bool,
    ) -> impl IntoResponse {
        info!("Received VC info: {:?}", vc_info);
        match app_state.credentials.get(&credential_id) {
            Some(credential_store_item) => {
                let credential_signed = TrustchainIssuerHTTPHandler::issue_credential(
                    credential_store_item,
                    Some(&vc_info.subject_id),
                    app_state.verifier.resolver(),
                    rss,
                )
                .await?;
                Ok((StatusCode::OK, Json(credential_signed)))
            }
            None => Err(TrustchainHTTPError::CredentialDoesNotExist),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::HTTPConfig, errors::TrustchainHTTPError, server::TrustchainRouter, state::AppState,
    };
    use axum_test_helper::TestClient;
    use bitcoin::Network;
    use hyper::StatusCode;
    use lazy_static::lazy_static;
    use serde_json::json;
    use ssi::{
        jsonld::ContextLoader,
        one_or_many::OneOrMany,
        vc::{Credential, CredentialSubject, Issuer, URI},
    };
    use std::{collections::HashMap, sync::Arc};
    use trustchain_core::{utils::canonicalize, verifier::Verifier};
    use trustchain_ion::utils::{init, BITCOIN_NETWORK};
    use trustchain_ion::{trustchain_resolver, verifier::TrustchainVerifier};

    // The root event time of DID documents in `trustchain-ion/src/data.rs` used for unit tests and the test below.
    const ROOT_EVENT_TIME_1: u64 = 1666265405;
    const TESTNET4_ROOT_EVENT_TIME_1: u64 = 1766953540;

    const ISSUER_DID: &str = "did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q";
    lazy_static! {
        /// Lazy static reference to core configuration loaded from `trustchain_config.toml`.
        pub static ref TEST_HTTP_CONFIG: HTTPConfig = HTTPConfig {
            server_did: Some(ISSUER_DID.to_string()),
            ..Default::default()
        };
    }

    const CREDENTIALS: &str = r#"{
        "46cb84e2-fa10-11ed-a0d4-bbb4e61d1556" : {
            "did": "did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q",
            "credential": {
                "@context" : [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/credentials/examples/v1"
                ],
                "id": "urn:uuid:46cb84e2-fa10-11ed-a0d4-bbb4e61d1556",
                "credentialSubject" : {
                "degree" : {
                    "college" : "University of Oxbridge",
                    "name" : "Bachelor of Arts",
                    "type" : "BachelorDegree"
                },
                "familyName" : "Bloggs",
                "givenName" : "Jane"
                },
                "type" : [
                "VerifiableCredential"
                ]
            }
        }
    }
    "#;

    const TESTNET4_CREDENTIALS: &str = r#"{
        "46cb84e2-fa10-11ed-a0d4-bbb4e61d1556" : {
            "did": "did:ion:test:EiBsaims7YMtoe3XYZ-7nQ-CGBGBsZQUIIfTRAh0Mrd8Sw",
            "credential": {
                "@context" : [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/credentials/examples/v1"
                ],
                "id": "urn:uuid:46cb84e2-fa10-11ed-a0d4-bbb4e61d1556",
                "credentialSubject" : {
                "degree" : {
                    "college" : "University of Oxbridge",
                    "name" : "Bachelor of Arts",
                    "type" : "BachelorDegree"
                },
                "familyName" : "Bloggs",
                "givenName" : "Jane"
                },
                "type" : [
                "VerifiableCredential"
                ]
            }
        }
    }
    "#;

    // Issuer integration tests
    #[tokio::test]
    #[ignore = "integration test requires ION, MongoDB, IPFS and Bitcoin RPC"]
    async fn test_get_issuer_offer() {
        let state = Arc::new(AppState::new_with_cache(
            TEST_HTTP_CONFIG.to_owned(),
            serde_json::from_str(CREDENTIALS).unwrap(),
            HashMap::new(),
        ));
        let app = TrustchainRouter::from(state.clone()).into_router();
        // Get offer for valid credential
        let uid = "46cb84e2-fa10-11ed-a0d4-bbb4e61d1556".to_string();
        let uri = format!("/vc/issuer/{uid}");
        let client = TestClient::new(app);
        let response = client.get(&uri).send().await;
        assert_eq!(response.status(), StatusCode::OK);
        let mut actual_offer = response.json::<CredentialOffer>().await;
        let credential_store_item = state.credentials.get(&uid).unwrap().clone();
        let mut credential = credential_store_item.credential;
        credential.issuer = Some(ssi::vc::Issuer::URI(ssi::vc::URI::String(
            credential_store_item.issuer_did.to_string(),
        )));
        let mut expected_offer = CredentialOffer::generate(&credential, &uid);

        // Set expiry to None as will be different
        expected_offer.expires = None;
        actual_offer.expires = None;

        // Check offers are equal
        assert_eq!(
            canonicalize(&expected_offer).unwrap(),
            canonicalize(&actual_offer).unwrap()
        );

        // Try to get an offer for non-existent credential
        let id = "46cb84e2-fa10-11ed-a0d4-bbb4e61d1555".to_string();
        let path = format!("/vc/issuer/{id}");
        let app = TrustchainRouter::from(state.clone()).into_router();
        let client = TestClient::new(app);
        let response = client.get(&path).send().await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response.text().await,
            json!({"error":TrustchainHTTPError::CredentialDoesNotExist.to_string()}).to_string()
        );
    }

    #[tokio::test]
    #[ignore = "integration test requires ION, MongoDB, IPFS and Bitcoin RPC"]
    async fn test_post_issuer_credential() {
        init();

        let credentials = match BITCOIN_NETWORK
            .as_ref()
            .expect("Integration test requires Bitcoin")
        {
            Network::Testnet => CREDENTIALS,
            Network::Testnet4 => TESTNET4_CREDENTIALS,
            network @ _ => {
                panic!("No test fixtures for network: {:?}", network);
            }
        };

        let app = TrustchainRouter::from(Arc::new(AppState::new_with_cache(
            TEST_HTTP_CONFIG.to_owned(),
            serde_json::from_str(credentials).unwrap(),
            HashMap::new(),
        )))
        .into_router();
        let id = "46cb84e2-fa10-11ed-a0d4-bbb4e61d1556".to_string();
        let expected_subject_id = "did:example:284b3f34fad911ed9aea439566dd422a".to_string();
        let path = format!("/vc/issuer/{id}");
        let client = TestClient::new(app);
        let response = client
            .post(&path)
            .json(&VcInfo {
                subject_id: expected_subject_id.to_string(),
            })
            .send()
            .await;
        // Test response
        assert_eq!(response.status(), StatusCode::OK);
        let credential = response.json::<Credential>().await;

        // Test credential subject ID
        match credential.credential_subject {
            OneOrMany::One(CredentialSubject {
                id: Some(URI::String(ref actual_subject_id)),
                property_set: _,
            }) => assert_eq!(actual_subject_id.to_string(), expected_subject_id),
            _ => panic!(),
        }

        // Test signature
        let verifier = TrustchainVerifier::new(trustchain_resolver("http://localhost:3000/"));
        let verify_credential_result = credential
            .verify(
                None,
                verifier.resolver().as_did_resolver(),
                &mut ContextLoader::default(),
            )
            .await;
        assert!(verify_credential_result.errors.is_empty());

        let expected_timestamp = match BITCOIN_NETWORK
            .as_ref()
            .expect("Integration test requires Bitcoin")
        {
            Network::Testnet => 1666265405,
            Network::Testnet4 => 1766953540,
            network @ _ => {
                panic!("No test fixtures for network: {:?}", network);
            }
        };

        // Test valid Trustchain issuer DID
        match credential.issuer {
            Some(Issuer::URI(URI::String(issuer))) => {
                assert!(verifier.verify(&issuer, expected_timestamp).await.is_ok())
            }
            _ => panic!("No issuer present."),
        }
    }

    #[tokio::test]
    #[ignore = "integration test requires ION, MongoDB, IPFS and Bitcoin RPC"]
    async fn test_post_issuer_rss_credential() {
        init();

        let credentials = match BITCOIN_NETWORK
            .as_ref()
            .expect("Integration test requires Bitcoin")
        {
            Network::Testnet => CREDENTIALS,
            Network::Testnet4 => TESTNET4_CREDENTIALS,
            network @ _ => {
                panic!("No test fixtures for network: {:?}", network);
            }
        };

        let app = TrustchainRouter::from(Arc::new(AppState::new_with_cache(
            TEST_HTTP_CONFIG.to_owned(),
            serde_json::from_str(credentials).unwrap(),
            HashMap::new(),
        )))
        .into_router();
        let id = "46cb84e2-fa10-11ed-a0d4-bbb4e61d1556".to_string();
        let expected_subject_id = "did:example:284b3f34fad911ed9aea439566dd422a".to_string();
        let path = format!("/vc_rss/issuer/{id}");
        let client = TestClient::new(app);
        let response = client
            .post(&path)
            .json(&VcInfo {
                subject_id: expected_subject_id.to_string(),
            })
            .send()
            .await;
        // Test response
        assert_eq!(response.status(), StatusCode::OK);
        let credential = response.json::<Credential>().await;

        // Test credential subject ID
        match credential.credential_subject {
            OneOrMany::One(CredentialSubject {
                id: Some(URI::String(ref actual_subject_id)),
                property_set: _,
            }) => assert_eq!(actual_subject_id.to_string(), expected_subject_id),
            _ => panic!(),
        }

        // Test signature
        let verifier = TrustchainVerifier::new(trustchain_resolver("http://localhost:3000/"));
        let verify_credential_result = credential
            .verify(
                None,
                verifier.resolver().as_did_resolver(),
                &mut ContextLoader::default(),
            )
            .await;
        assert!(verify_credential_result.errors.is_empty());

        // Test valid Trustchain issuer DID
        let root_event_time = match BITCOIN_NETWORK
            .as_ref()
            .expect("Integration test requires Bitcoin")
        {
            Network::Testnet => ROOT_EVENT_TIME_1,
            Network::Testnet4 => TESTNET4_ROOT_EVENT_TIME_1,
            network @ _ => {
                panic!("No test fixtures for network: {:?}", network);
            }
        };

        match credential.issuer {
            Some(Issuer::URI(URI::String(issuer))) => {
                assert!(verifier.verify(&issuer, root_event_time).await.is_ok())
            }
            _ => panic!("No issuer present."),
        }
    }
}
