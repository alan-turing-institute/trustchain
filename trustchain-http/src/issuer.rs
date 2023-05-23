use crate::errors::TrustchainHTTPError;
use crate::qrcode::str_to_qr_code_html;
use crate::state::AppState;
use crate::ISSUER_DID;
use async_trait::async_trait;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse};
use axum::Json;
use chrono::Utc;
use lazy_static::lazy_static;
use log::info;
use serde::{Deserialize, Serialize};
use serde_json::json;
use ssi::did_resolve::DIDResolver;
use ssi::one_or_many::OneOrMany;
use ssi::vc::Credential;
use ssi::vc::VCDateTime;
use std::sync::Arc;
use trustchain_core::issuer::Issuer;
use trustchain_core::resolver::Resolver;
use trustchain_core::verifier::Verifier;
use trustchain_ion::attestor::IONAttestor;
use uuid::Uuid;

lazy_static! {
    static ref TEMPLATE: Credential = {
        let home = std::env::var("HOME").unwrap();
        let file_str = format!("{home}/.trustchain/credentials/credential_template.jsonld");
        serde_json::from_str(
            &std::fs::read_to_string(file_str).expect("No template credential file."),
        )
        .unwrap()
    };
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
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
    pub fn generate(template: &Credential, id: &str) -> Self {
        let mut credential: Credential = template.to_owned();
        credential.id = Some(ssi::vc::URI::String(format!("urn:uuid:{}", id)));
        Self::new(credential)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VcInfo {
    subject_id: String,
}

/// An API for a Trustchain verifier server.
#[async_trait]
pub trait TrustchainIssuerHTTP {
    /// Issues an offer for a verifiable credential
    fn generate_credential_offer(template: &Credential, id: &str) -> CredentialOffer;
    /// Issues a verifiable credential (should it return `Credential` or `String`)
    async fn issue_credential<T: DIDResolver + Send + Sync>(
        credential: &Credential,
        subject_id: Option<&str>,
        credential_id: &str,
        resolver: &Resolver<T>,
    ) -> Credential;
}

/// Type for implementing the TrustchainIssuerHTTP trait that will contain additional handler methods.
pub struct TrustchainIssuerHTTPHandler;

#[async_trait]
impl TrustchainIssuerHTTP for TrustchainIssuerHTTPHandler {
    fn generate_credential_offer(template: &Credential, id: &str) -> CredentialOffer {
        CredentialOffer::generate(template, id)
    }

    async fn issue_credential<T: DIDResolver + Send + Sync>(
        credential: &Credential,
        subject_id: Option<&str>,
        credential_id: &str,
        resolver: &Resolver<T>,
    ) -> Credential {
        let mut credential = credential.to_owned();
        credential.id = Some(ssi::vc::URI::String(format!("urn:uuid:{}", credential_id)));
        let now = chrono::offset::Utc::now();
        credential.issuance_date = Some(VCDateTime::from(now));
        if let Some(subject_id_str) = subject_id {
            if let OneOrMany::One(ref mut subject) = credential.credential_subject {
                subject.id = Some(ssi::vc::URI::String(subject_id_str.to_string()));
            }
        }

        let issuer = IONAttestor::new(ISSUER_DID);

        issuer.sign(&credential, None, resolver).await.unwrap()
    }
}

impl TrustchainIssuerHTTPHandler {
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
        Path(id): Path<String>,
        State(app_state): State<Arc<AppState>>,
    ) -> impl IntoResponse {
        app_state
            .credentials
            .get(&id)
            .ok_or(TrustchainHTTPError::CredentialDoesNotExist)
            .map(|credential| {
                (
                    StatusCode::OK,
                    Json(TrustchainIssuerHTTPHandler::generate_credential_offer(
                        credential, &id,
                    )),
                )
            })
    }
    /// Receives subject DID in response to offer and returns signed credential.
    pub async fn post_issuer(
        (Path(id), Json(vc_info)): (Path<String>, Json<VcInfo>),
        app_state: Arc<AppState>,
    ) -> impl IntoResponse {
        info!("Received VC info: {:?}", vc_info);
        match app_state.credentials.get(&id) {
            Some(credential) => {
                let credential_signed = TrustchainIssuerHTTPHandler::issue_credential(
                    credential,
                    None,
                    &id,
                    app_state.verifier.resolver(),
                )
                .await;
                Ok((StatusCode::OK, Json(credential_signed)))
            }
            None => Err(TrustchainHTTPError::CredentialDoesNotExist),
        }
    }
}

#[cfg(test)]
mod tests {
    use axum_test_helper::TestClient;
    use hyper::StatusCode;

    use crate::{config::ServerConfig, issuer::VcInfo, server::router};

    // TODO: add test flexibility with credential offer and to be signed created in tests

    // Issuer integration tests
    #[tokio::test]
    #[ignore = "integration test requires ION, MongoDB, IPFS and Bitcoin RPC"]
    async fn test_get_issuer_offer() {
        let app = router(ServerConfig::default());
        let uid = "abc";
        let uri = format!("/vc/issuer/{uid}");
        let client = TestClient::new(app);
        let response = client.get(&uri).send().await;
        assert_eq!(response.status(), StatusCode::OK);
        println!("{:?}", response.text().await);
        // assert_eq!(
        //     canonicalize_str::<VerificationBundle>(&response.text().await).unwrap(),
        //     canonicalize_str::<VerificationBundle>(TEST_ROOT_PLUS_2_BUNDLE).unwrap()
        // );
    }

    #[tokio::test]
    #[ignore = "integration test requires ION, MongoDB, IPFS and Bitcoin RPC"]
    async fn test_post_issuer_credential() {
        let app = router(ServerConfig::default());
        let uid = "abc";
        let uri = format!("/vc/issuer/{uid}");
        let client = TestClient::new(app);
        let response = client
            .post(&uri)
            .json(&VcInfo {
                subject_id: "abc".to_string(),
            })
            .send()
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        println!("{:?}", response.text().await);
    }
}
