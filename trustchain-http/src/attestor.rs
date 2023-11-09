use crate::attestation_encryption_utils::{josekit_to_ssi_jwk, ssi_to_josekit_jwk};
use crate::attestation_utils::{
    attestation_request_path, ElementwiseSerializeDeserialize, IdentityCRInitiation,
};
use crate::{errors::TrustchainHTTPError, state::AppState};
use async_trait::async_trait;
use axum::extract::path;
use axum::{
    response::{Html, IntoResponse, Response},
    Json,
};
use hyper::StatusCode;
use log::{debug, info, log};
use rand::Rng;
use rand::{distributions::Alphanumeric, thread_rng};
use serde::{Deserialize, Serialize};
use serde_json::to_string_pretty;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::{fs::OpenOptions, path::Path, path::PathBuf, sync::Arc};
use trustchain_core::TRUSTCHAIN_DATA;

// Fields:
// - API access token
// - temporary public key
// - name of DE organisation ("name_downstream")
// - name of individual operator within DE responsible for the request

// /// Writes received attestation request to unique path derived from the public key for the interaction.
// fn write_attestation_info(
//     attestation_info: &IdentityCRInitiation,
// ) -> Result<(), TrustchainHTTPError> {
//     // Get environment for TRUSTCHAIN_DATA

//     let directory = attestion_request_path(&attestation_info.temp_p_key.unwrap().to_string())?;

//     // Make directory if non-existent
//     // Equivalent of os.makedirs(exist_ok=True) in python
//     std::fs::create_dir_all(&directory)
//         .map_err(|_| TrustchainHTTPError::FailedAttestationRequest)?;

//     // Check if initial request exists ("attestation_info.json"), if yes, return InternalServerError
//     let full_path = directory.join("attestation_info.json");

//     if full_path.exists() {
//         return Err(TrustchainHTTPError::FailedAttestationRequest);
//     }

//     // If not, write to file
//     // Open the new file
//     let mut file = OpenOptions::new()
//         .create(true)
//         .write(true)
//         .truncate(true)
//         .open(full_path)
//         .map_err(|_| TrustchainHTTPError::FailedAttestationRequest)?;

//     // Write to file
//     writeln!(file, "{}", &to_string_pretty(attestation_info).unwrap())
//         .map_err(|_| TrustchainHTTPError::FailedAttestationRequest)?;

//     // Else do something?

//     Ok(())
// }

// Encryption: https://github.com/hidekatsu-izuno/josekit-rs#signing-a-jwt-by-ecdsa

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
        Json(attestation_initiation): Json<IdentityCRInitiation>,
        // app_state: Arc<AppState>,
    ) -> impl IntoResponse {
        info!("Received attestation info: {:?}", attestation_initiation);
        let temp_p_key_ssi =
            josekit_to_ssi_jwk(attestation_initiation.temp_p_key.as_ref().unwrap());
        let path = attestation_request_path(&temp_p_key_ssi.unwrap()).unwrap();
        // create directory and save attestation initation to file
        let _ = std::fs::create_dir_all(&path);
        let _ = attestation_initiation.elementwise_serialize(&path).map(|_| (StatusCode::OK, Html("Received request. Please wait for operator to contact you through an alternative channel.")));
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        attestation_utils::RequesterDetails, config::HTTPConfig, server::TrustchainRouter,
    };
    use axum_test_helper::TestClient;

    use super::*;

    // TODO: add this key when switched to JWK
    use crate::data::TEST_TEMP_KEY;

    // Attestor integration tests
    // TODO: make test better
    #[tokio::test]
    #[ignore = "integration test requires ION, MongoDB, IPFS and Bitcoin RPC"]
    async fn test_post_initiation() {
        let attestation_initiation: IdentityCRInitiation = IdentityCRInitiation {
            temp_p_key: Some(serde_json::from_str(TEST_TEMP_KEY).unwrap()),
            requester_details: Some(RequesterDetails {
                requester_org: "myTrustworthyEntity".to_string(),
                operator_name: "trustworthyOperator".to_string(),
            }),
        };
        let initiation_json = serde_json::to_string_pretty(&attestation_initiation).unwrap();
        println!("Attestation initiation: {:?}", initiation_json);
        let app = TrustchainRouter::from(HTTPConfig::default()).into_router();
        let uri = "/did/attestor/initiate".to_string();
        let client = TestClient::new(app);

        let response = client.post(&uri).json(&attestation_initiation).send().await;
        assert_eq!(response.status(), 200);
        println!("Response text: {:?}", response.text().await);
        // assert_eq!(response.text().await, "Received request. Please wait for operator to contact you through an alternative channel.");
    }
}
