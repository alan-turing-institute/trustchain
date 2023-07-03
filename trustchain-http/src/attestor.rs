use crate::{errors::TrustchainHTTPError, state::AppState};
use async_trait::async_trait;
use axum::{
    response::{Html, IntoResponse, Response},
    Json,
};
use hyper::StatusCode;
use log::{debug, info, log};
use serde::{Deserialize, Serialize};
use serde_json::to_string_pretty;
use sha2::{Digest, Sha256};
use ssi::jwk::JWK;
use std::io::Write;
use std::{fs::OpenOptions, path::Path, path::PathBuf, sync::Arc};
use trustchain_core::TRUSTCHAIN_DATA;

// Fields:
// - API access token
// - temporary public key
// - name of DE organisation ("name_downstream")
// - name of individual operator within DE responsible for the request

/// Writes received attestation request to unique path derived from the public key for the interaction.
fn write_attestation_info(attestation_info: &AttestationInfo) -> Result<(), TrustchainHTTPError> {
    // Get environment for TRUSTCHAIN_DATA

    let directory = attestion_request_path(&attestation_info.temp_pub_key)?;

    // Make directory if non-existent
    // Equivalent of os.makedirs(exist_ok=True) in python
    std::fs::create_dir_all(&directory)
        .map_err(|_| TrustchainHTTPError::FailedAttestationRequest)?;

    // Check if initial request exists ("attestation_info.json"), if yes, return InternalServerError
    let full_path = directory.join("attestation_info.json");

    if full_path.exists() {
        return Err(TrustchainHTTPError::FailedAttestationRequest);
    }

    // If not, write to file
    // Open the new file
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(full_path)
        .map_err(|_| TrustchainHTTPError::FailedAttestationRequest)?;

    // Write to file
    writeln!(file, "{}", &to_string_pretty(attestation_info).unwrap())
        .map_err(|_| TrustchainHTTPError::FailedAttestationRequest)?;

    // Else do something?

    Ok(())
}

/// Returns unique path name for a specific attestation request derived from public key for the interaction.
fn attestion_request_path(pub_key: &str) -> Result<PathBuf, TrustchainHTTPError> {
    // Root path in TRUSTCHAIN_DATA
    let path: String = std::env::var(TRUSTCHAIN_DATA)
        .map_err(|_| TrustchainHTTPError::FailedAttestationRequest)?;
    // Use hash of temp_pub_key
    Ok(Path::new(path.as_str())
        .join("attestation_requests")
        .join(attestation_request_id(pub_key)))
}

pub fn attestation_request_id(pub_key: &str) -> String {
    hex::encode(Sha256::digest(pub_key))
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AttestationInfo {
    // api_access_token: JWT,
    // temp_pub_key: JWK,
    api_access_token: String,
    temp_pub_key: String,
    // TODO: change temp_pub_key
    // temp_pub_key: JWK,
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
    /// Processes initial attestation request and provided data
    pub async fn post_initiation(
        Json(attestation_info): Json<AttestationInfo>,
        // app_state: Arc<AppState>,
    ) -> impl IntoResponse {
        info!("Received attestation info: {:?}", attestation_info);

        match write_attestation_info(&attestation_info) {
            Ok(()) => {
                (
                    StatusCode::OK,
                    Html("Received request. Please wait for operator to contact you through an alternative channel."),
                )
            }
            Err(_error) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Html("Attestation request failed."),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{config::HTTPConfig, server::TrustchainRouter};
    use axum::extract;
    use axum_test_helper::TestClient;
    use lazy_static::lazy_static;
    use trustchain_core::utils::init;

    use super::*;

    // TODO: add this key when switched to JWK
    const TEST_KEY: &str =
        r#"{"kty":"OKP","crv":"Ed25519","x":"B2J8eJfFljEnKX9yt9_V4TCwcL8rd4qtD7T2Bz4TX0s"}"#;
    const TEST_ATTESTATION_INFO: &str = r#"{
        "apiAccessToken": "abcd",
        "tempPubKey": "some_string",
        "nameDownstream": "myTrustworthyEntity",
        "nameOperator": "trustworthyOperator"
    }"#;

    #[test]
    fn test_key() {
        let key: JWK = serde_json::from_str(TEST_KEY).unwrap();
    }

    #[test]
    fn test_write_attestation_info() {
        init();
        let expected_attestation_info: AttestationInfo =
            serde_json::from_str(TEST_ATTESTATION_INFO).unwrap();
        // Get expected path
        let expected_path =
            attestion_request_path(&expected_attestation_info.temp_pub_key).unwrap();
        println!("The test path is: {:?}", expected_path);

        // Write to file
        assert!(write_attestation_info(&expected_attestation_info).is_ok());

        // Check directory exists
        assert!(expected_path.exists());

        // Check file deserializes to ATTESTATION_INFO
        let file_content =
            std::fs::read_to_string(expected_path.join("attestation_info.json")).unwrap();
        println!("The file attestation_info.json contains: {}", file_content);

        let actual_attesation_info: AttestationInfo = serde_json::from_str(&file_content).unwrap();
        assert_eq!(expected_attestation_info.clone(), actual_attesation_info);
    }

    // Attestor integration tests
    // TODO: make test better
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
