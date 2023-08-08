use crate::errors::TrustchainHTTPError;
use crate::qrcode::str_to_qr_code_html;
use crate::state::AppState;
use async_trait::async_trait;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse};
use axum::Json;
use chrono::Utc;
use log::info;
use serde::{Deserialize, Serialize};
use ssi::did_resolve::DIDResolver;
use ssi::one_or_many::OneOrMany;
use ssi::vc::Credential;
use ssi::vc::VCDateTime;
use std::sync::Arc;
use trustchain_core::issuer::Issuer;
use trustchain_core::resolver::Resolver;
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
    /// Generates credential offer.
    pub fn generate(credential: &Credential, id: &str) -> Self {
        let mut credential: Credential = credential.to_owned();
        credential.id = Some(ssi::vc::URI::String(format!("urn:uuid:{}", id)));
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
    fn generate_credential_offer(
        template: &Credential,
        id: &str,
        issuer_did: &str,
    ) -> CredentialOffer;
    /// Issues a verifiable credential (should it return `Credential` or `String`)
    async fn issue_credential<T: DIDResolver + Send + Sync>(
        credential: &Credential,
        subject_id: Option<&str>,
        issuer_did: &str,
        resolver: &Resolver<T>,
    ) -> Result<Credential, TrustchainHTTPError>;
}

/// Type for implementing the TrustchainIssuerHTTP trait that will contain additional handler methods.
pub struct TrustchainIssuerHTTPHandler;

#[async_trait]
impl TrustchainIssuerHTTP for TrustchainIssuerHTTPHandler {
    fn generate_credential_offer(
        template: &Credential,
        id: &str,
        issuer_did: &str,
    ) -> CredentialOffer {
        let mut credential = template.to_owned();
        credential.issuer = Some(ssi::vc::Issuer::URI(ssi::vc::URI::String(
            issuer_did.to_string(),
        )));
        CredentialOffer::generate(&credential, id)
    }

    async fn issue_credential<T: DIDResolver + Send + Sync>(
        credential: &Credential,
        subject_id: Option<&str>,
        issuer_did: &str,
        resolver: &Resolver<T>,
    ) -> Result<Credential, TrustchainHTTPError> {
        let mut credential = credential.to_owned();
        credential.issuer = Some(ssi::vc::Issuer::URI(ssi::vc::URI::String(
            issuer_did.to_string(),
        )));
        let now = chrono::offset::Utc::now();
        credential.issuance_date = Some(VCDateTime::from(now));
        if let Some(subject_id_str) = subject_id {
            if let OneOrMany::One(ref mut subject) = credential.credential_subject {
                subject.id = Some(ssi::vc::URI::String(subject_id_str.to_string()));
            }
        }
        let issuer = IONAttestor::new(issuer_did);
        Ok(issuer.sign(&credential, None, resolver, None).await?)
    }
}

impl TrustchainIssuerHTTPHandler {
    /// Generates QR code to display to holder to receive requested credential.
    pub async fn get_issuer_qrcode(State(app_state): State<Arc<AppState>>) -> Html<String> {
        // TODO: update to take query param entered by user.
        let id = "7426a2e8-f932-11ed-968a-4bb02079f142".to_string();
        // Generate a QR code for server address and combination of name and UUID
        let address_str = format!(
            "http://{}:{}/vc/issuer/{id}",
            app_state.config.host_reference, app_state.config.port
        );
        // Respond with the QR code as a png embedded in html
        Html(str_to_qr_code_html(&address_str, "Issuer"))
    }

    /// API endpoint taking the UUID of a VC. Response is the VC JSON.
    pub async fn get_issuer(
        Path(credential_id): Path<String>,
        State(app_state): State<Arc<AppState>>,
    ) -> impl IntoResponse {
        let issuer_did = app_state
            .config
            .issuer_did
            .as_ref()
            .ok_or(TrustchainHTTPError::NoCredentialIssuer)?;

        app_state
            .credentials
            .get(&credential_id)
            .ok_or(TrustchainHTTPError::CredentialDoesNotExist)
            .map(|credential| {
                (
                    StatusCode::OK,
                    Json(TrustchainIssuerHTTPHandler::generate_credential_offer(
                        credential,
                        &credential_id,
                        issuer_did,
                    )),
                )
            })
    }
    /// Receives subject DID in response to offer and returns signed credential.
    pub async fn post_issuer(
        (Path(credential_id), Json(vc_info)): (Path<String>, Json<VcInfo>),
        app_state: Arc<AppState>,
    ) -> impl IntoResponse {
        info!("Received VC info: {:?}", vc_info);
        let issuer_did = app_state
            .config
            .issuer_did
            .as_ref()
            .ok_or(TrustchainHTTPError::NoCredentialIssuer)?;
        match app_state.credentials.get(&credential_id) {
            Some(credential) => {
                let credential_signed = TrustchainIssuerHTTPHandler::issue_credential(
                    credential,
                    Some(&vc_info.subject_id),
                    issuer_did,
                    app_state.verifier.resolver(),
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
    use hyper::StatusCode;
    use lazy_static::lazy_static;
    use serde_json::json;
    use ssi::{
        one_or_many::OneOrMany,
        vc::{Credential, CredentialSubject, Issuer, URI},
    };
    use std::sync::Arc;
    use trustchain_core::{utils::canonicalize, verifier::Verifier};
    use trustchain_ion::{get_ion_resolver, verifier::IONVerifier};

    lazy_static! {
        /// Lazy static reference to core configuration loaded from `trustchain_config.toml`.
        pub static ref TEST_HTTP_CONFIG: HTTPConfig = HTTPConfig {
            issuer_did: Some("did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q".to_string()),
            ..Default::default()
        };
    }

    const CREDENTIALS: &str = r#"{
        "46cb84e2-fa10-11ed-a0d4-bbb4e61d1556" : {
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
    "#;

    // Issuer integration tests
    #[tokio::test]
    #[ignore = "integration test requires ION, MongoDB, IPFS and Bitcoin RPC"]
    async fn test_get_issuer_offer() {
        let state = Arc::new(AppState::new_with_cache(
            TEST_HTTP_CONFIG.to_owned(),
            serde_json::from_str(CREDENTIALS).unwrap(),
        ));
        let app = TrustchainRouter::from(state.clone()).into_router();
        // Get offer for valid credential
        let uid = "46cb84e2-fa10-11ed-a0d4-bbb4e61d1556".to_string();
        let uri = format!("/vc/issuer/{uid}");
        let client = TestClient::new(app);
        let response = client.get(&uri).send().await;
        assert_eq!(response.status(), StatusCode::OK);
        let mut actual_offer = response.json::<CredentialOffer>().await;
        let mut credential = state.credentials.get(&uid).unwrap().clone();
        credential.issuer = Some(ssi::vc::Issuer::URI(ssi::vc::URI::String(
            state.config.issuer_did.as_ref().unwrap().to_string(),
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
        let uid = "46cb84e2-fa10-11ed-a0d4-bbb4e61d1555".to_string();
        let uri = format!("/vc/issuer/{uid}");
        let app = TrustchainRouter::from(state.clone()).into_router();
        let client = TestClient::new(app);
        let response = client.get(&uri).send().await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response.text().await,
            json!({"error":TrustchainHTTPError::CredentialDoesNotExist.to_string()}).to_string()
        );
    }

    #[tokio::test]
    #[ignore = "integration test requires ION, MongoDB, IPFS and Bitcoin RPC"]
    async fn test_post_issuer_credential() {
        let app = TrustchainRouter::from(Arc::new(AppState::new_with_cache(
            TEST_HTTP_CONFIG.to_owned(),
            serde_json::from_str(CREDENTIALS).unwrap(),
        )))
        .into_router();
        let uid = "46cb84e2-fa10-11ed-a0d4-bbb4e61d1556".to_string();
        let expected_subject_id = "did:example:284b3f34fad911ed9aea439566dd422a".to_string();
        let uri = format!("/vc/issuer/{uid}");
        let client = TestClient::new(app);
        let response = client
            .post(&uri)
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
        let verifier = IONVerifier::new(get_ion_resolver("http://localhost:3000/"));
        let verify_credential_result = credential.verify(None, verifier.resolver()).await;
        assert!(verify_credential_result.errors.is_empty());

        // Test valid Trustchain issuer DID
        match credential.issuer {
            Some(Issuer::URI(URI::String(issuer))) => {
                assert!(verifier.verify(&issuer, 1666265405).await.is_ok())
            }
            _ => panic!("No issuer present."),
        }
    }
}
