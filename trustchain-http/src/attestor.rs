use async_trait::async_trait;
use axum::{
    response::{Html, IntoResponse},
    Json,
};
use hyper::StatusCode;
use log::{debug, info, log};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::state::AppState;
// use ssi::jwk::JWK;

// Fields:
// - API access token
// - temporary public key
// - name of DE organisation ("name_downstream")
// - name of individual operator within DE responsible for the request

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttestationInfo {
    // api_access_token: JWT,
    // temp_pub_key: JWK,
    api_access_token: String,
    temp_pub_key: String,
    name_downstream: String,
    name_operator: String,
}

#[async_trait]
pub trait TrustchainAttestorHTTP {}

/// Type for implementing the TrustchainIssuerHTTP trait that will contain additional handler methods.
pub struct TrustchainAttestorHTTPHandler;

#[async_trait]
impl TrustchainAttestorHTTP for TrustchainAttestorHTTPHandler {
    // async fn issue_credential<T: DIDResolver + Send + Sync>(
    //     credential: &Credential,
    //     subject_id: Option<&str>,
    //     issuer_did: &str,
    //     resolver: &Resolver<T>,
    // ) -> Result<Credential, TrustchainHTTPError> {
    //     let mut credential = credential.to_owned();
    //     credential.issuer = Some(ssi::vc::Issuer::URI(ssi::vc::URI::String(
    //         issuer_did.to_string(),
    //     )));
    //     let now = chrono::offset::Utc::now();
    //     credential.issuance_date = Some(VCDateTime::from(now));
    //     if let Some(subject_id_str) = subject_id {
    //         if let OneOrMany::One(ref mut subject) = credential.credential_subject {
    //             subject.id = Some(ssi::vc::URI::String(subject_id_str.to_string()));
    //         }
    //     }
    //     let issuer = IONAttestor::new(issuer_did);
    //     Ok(issuer.sign(&credential, None, resolver).await?)
    // }
}

impl TrustchainAttestorHTTPHandler {
    /// Receives subject DID in response to offer and returns signed credential.
    pub async fn post_initiation(
        Json(attestation_info): Json<AttestationInfo>,
        // app_state: Arc<AppState>,
    ) -> impl IntoResponse {
        info!("Received attestation info: {:?}", attestation_info);
        (StatusCode::OK, Html("Hello world!"))
    }
}

#[cfg(test)]
mod tests {
    use axum_test_helper::TestClient;

    use crate::{config::HTTPConfig, server::TrustchainRouter};

    use super::*;

    // Attestor integration tests
    #[tokio::test]
    #[ignore = "integration test requires ION, MongoDB, IPFS and Bitcoin RPC"]
    async fn test_post_initiation() {
        let app = TrustchainRouter::from(HTTPConfig::default()).into_router();
        let uri = "/did/attestor/initiate".to_string();
        let client = TestClient::new(app);

        let response = client
            .post(&uri)
            .json(&AttestationInfo {
                api_access_token: "a".to_string(),
                name_downstream: "b".to_string(),
                name_operator: "c".to_string(),
                temp_pub_key: "d".to_string(),
            })
            .send()
            .await;
        assert_eq!(response.status(), 200);
        assert_eq!(response.text().await, "Hello world!");
    }
}
