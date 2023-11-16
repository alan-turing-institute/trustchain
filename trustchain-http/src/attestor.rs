use crate::attestation_encryption_utils::{
    josekit_to_ssi_jwk, ssi_to_josekit_jwk, DecryptVerify, Entity, SignEncrypt,
};
use crate::attestation_utils::{
    attestation_request_path, CRIdentityChallenge, ElementwiseSerializeDeserialize,
    IdentityCRInitiation, Nonce, TrustchainCRError,
};

use async_trait::async_trait;
use axum::extract::Path;
use axum::{
    response::{Html, IntoResponse},
    Json,
};
use hyper::StatusCode;
use josekit::jwk::Jwk;
use josekit::jwt::JwtPayload;
use log::info;

use serde::{Deserialize, Serialize};

use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;
use std::result;

use trustchain_core::utils::generate_key;
use trustchain_core::TRUSTCHAIN_DATA;
use trustchain_ion::attestor::IONAttestor;

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

#[derive(Serialize)]
struct CustomResponse {
    message: String,
    path: Option<String>,
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

    pub async fn post_response(
        Path((did, key_id)): Path<(String, String)>,
        Json(response): Json<String>,
    ) -> impl IntoResponse {
        // get keys (attestor secret key, temp public key)
        let trustchain_dir: String = std::env::var(TRUSTCHAIN_DATA).unwrap();
        let path = PathBuf::new()
            .join(trustchain_dir)
            .join("attestation_requests")
            .join(&key_id);
        if !path.exists() {
            panic!("Provided attestation request not found. Path does not exist.");
        }
        // deserialise
        let mut identity_challenge = CRIdentityChallenge::new()
            .elementwise_deserialize(&path)
            .unwrap()
            .unwrap();
        // get signing key from ION attestor
        let ion_attestor = IONAttestor::new(&did);
        let signing_keys = ion_attestor.signing_keys().unwrap();
        let signing_key_ssi = signing_keys.first().unwrap();
        let signing_key = ssi_to_josekit_jwk(&signing_key_ssi);
        // get temp public key
        info!("Path: {:?}", path);
        let temp_key_path = path.join("temp_p_key.json");
        let file = File::open(&temp_key_path).unwrap();
        let reader = BufReader::new(file);
        let temp_p_key_ssi = serde_json::from_reader(reader)
            .map_err(|_| TrustchainCRError::FailedToDeserialize)
            .unwrap();
        let temp_p_key = ssi_to_josekit_jwk(&temp_p_key_ssi).unwrap();

        // decrypt and verify
        let attestor = Entity {};
        let payload = attestor
            .decrypt_and_verify(response.clone(), &signing_key.unwrap(), &temp_p_key)
            .unwrap();

        let result = verify_nonce(payload, &path);
        match result {
            Ok(_) => {
                identity_challenge.identity_response_signature = Some(response.clone());
                identity_challenge.elementwise_serialize(&path).unwrap();
                let respone = CustomResponse {
                    message: "Verification successful. Please use the provided path to initiate the second part of the attestation process.".to_string(),
                    path:Some(format!("/did/attestor/content/initiate/{}", &key_id)),
                };
                (StatusCode::OK, Json(respone));
            }
            Err(_) => {
                let respone = CustomResponse {
                    message: "Verification failed. Please try again.".to_string(),
                    path: None,
                };
                (StatusCode::BAD_REQUEST, Json(respone));
            }
        }
    }
}

pub fn present_identity_challenge(
    did: &str,
    temp_p_key: &Jwk,
) -> Result<CRIdentityChallenge, TrustchainCRError> {
    // generate nonce and update key
    let nonce = Nonce::new();
    let update_s_key_ssi = generate_key();
    let update_p_key_ssi = update_s_key_ssi.to_public();
    let update_s_key = ssi_to_josekit_jwk(&update_s_key_ssi)
        .map_err(|_| TrustchainCRError::FailedToGenerateKey)?;
    let update_p_key = ssi_to_josekit_jwk(&update_p_key_ssi)
        .map_err(|_| TrustchainCRError::FailedToGenerateKey)?;
    // let update_p_key_string = serde_json::to_string_pretty(&update_p_key)?;

    let mut identity_challenge = CRIdentityChallenge {
        update_p_key: Some(update_p_key),
        update_s_key: Some(update_s_key),
        identity_nonce: Some(nonce),
        identity_challenge_signature: None,
        identity_response_signature: None,
    };

    // make payload
    let payload = JwtPayload::try_from(&identity_challenge).unwrap();

    // get signing key from ION attestor
    let ion_attestor = IONAttestor::new(did);
    let signing_keys = ion_attestor.signing_keys().unwrap();
    let signing_key_ssi = signing_keys.first().unwrap();
    let signing_key =
        ssi_to_josekit_jwk(&signing_key_ssi).map_err(|_| TrustchainCRError::FailedToGenerateKey)?;

    // sign (with pub key) and encrypt (with temp_p_key) payload
    let attestor = Entity {};
    let signed_encrypted_challenge =
        attestor.sign_and_encrypt_claim(&payload, &signing_key, &temp_p_key);
    identity_challenge.identity_challenge_signature = Some(signed_encrypted_challenge?);

    Ok(identity_challenge)
}

fn verify_nonce(payload: JwtPayload, path: &PathBuf) -> Result<(), TrustchainCRError> {
    // get nonce from payload
    let nonce = payload.claim("identity_nonce").unwrap().as_str().unwrap();
    // deserialise expected nonce
    let nonce_path = path.join("identity_nonce.json");
    let file = File::open(&nonce_path).unwrap();
    let reader = BufReader::new(file);
    let expected_nonce: String =
        serde_json::from_reader(reader).map_err(|_| TrustchainCRError::FailedToDeserialize)?;

    if nonce != expected_nonce {
        return Err(TrustchainCRError::FailedToVerifyNonce);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::data::TEST_UPDATE_KEY;
    use crate::{
        attestation_utils::RequesterDetails, config::HTTPConfig, server::TrustchainRouter,
    };
    use axum_test_helper::TestClient;
    use ssi::jwk::JWK;
    use tempfile::tempdir;

    use super::*;

    // TODO: add this key when switched to JWK
    use crate::data::TEST_TEMP_KEY;

    // Attestor integration tests
    // TODO: make test better
    #[tokio::test]
    #[ignore = "integration test requires ION, MongoDB, IPFS and Bitcoin RPC"]
    async fn test_post_initiation() {
        let temp_s_key_ssi: JWK = serde_json::from_str(TEST_TEMP_KEY).unwrap();
        let temp_p_key_ssi = temp_s_key_ssi.to_public();
        let attestation_initiation: IdentityCRInitiation = IdentityCRInitiation {
            temp_s_key: Some(serde_json::from_str(TEST_TEMP_KEY).unwrap()),
            temp_p_key: Some(ssi_to_josekit_jwk(&temp_p_key_ssi).unwrap()),
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

    #[test]
    fn test_verify_nonce() {
        let temp_path = tempdir().unwrap().into_path();
        let expected_nonce = Nonce::from(String::from("test_nonce"));
        let identity_challenge = CRIdentityChallenge {
            update_p_key: serde_json::from_str(TEST_UPDATE_KEY).unwrap(),
            update_s_key: None,
            identity_nonce: Some(expected_nonce.clone()),
            identity_challenge_signature: None,
            identity_response_signature: None,
        };
        identity_challenge
            .elementwise_serialize(&temp_path)
            .unwrap();
        // make payload
        let payload = JwtPayload::try_from(&identity_challenge).unwrap();
        let result = verify_nonce(payload, &temp_path);
        assert!(result.is_ok());
    }
}
