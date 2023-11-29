use crate::attestation_encryption_utils::{
    extract_key_ids_and_jwk, josekit_to_ssi_jwk, ssi_to_josekit_jwk, DecryptVerify, Entity,
    SignEncrypt,
};
use crate::attestation_utils::{
    attestation_request_path, ContentCRChallenge, CustomResponse, ElementwiseSerializeDeserialize,
    IdentityCRChallenge, IdentityCRInitiation, Nonce, TrustchainCRError,
};
use crate::state::AppState;
use async_trait::async_trait;
use axum::extract::Path;
use axum::{response::IntoResponse, Json};
use hyper::StatusCode;
use josekit::jwk::Jwk;
use josekit::jwt::JwtPayload;
use log::info;

use trustchain_api::api::TrustchainDIDAPI;
use trustchain_api::TrustchainAPI;
use trustchain_core::verifier::Verifier;

use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;
use std::sync::Arc;

use trustchain_core::utils::generate_key;
use trustchain_core::TRUSTCHAIN_DATA;
use trustchain_ion::attestor::IONAttestor;

// Encryption: https://github.com/hidekatsu-izuno/josekit-rs#signing-a-jwt-by-ecdsa

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
    /// Handles a POST request for identity initiation (part 1 attestation CR).
    ///
    /// This function saves the attestation initiation to a file. The directory to which the information
    /// is saved is determined by the temp public key of the attestation initiation.
    pub async fn post_identity_initiation(
        Json(attestation_initiation): Json<IdentityCRInitiation>,
    ) -> impl IntoResponse {
        info!("Received attestation info: {:?}", attestation_initiation);
        let temp_p_key_ssi =
            josekit_to_ssi_jwk(attestation_initiation.temp_p_key.as_ref().unwrap());
        let path = attestation_request_path(&temp_p_key_ssi.unwrap()).unwrap();
        // create directory and save attestation initation to file
        let _ = std::fs::create_dir_all(&path);
        let result = attestation_initiation.elementwise_serialize(&path);
        match result {
            Ok(_) => {
                let response = CustomResponse {
                    message: "Received attestation request. Please wait for operator to contact you through an alternative channel.".to_string(),
                    data: None,
                };
                (StatusCode::OK, Json(response))
            }
            Err(_) => {
                let response = CustomResponse {
                    message: "Attestation request failed.".to_string(),
                    data: None,
                };
                (StatusCode::BAD_REQUEST, Json(response))
            }
        }
    }

    /// Handles a POST request for identity response.
    ///
    /// This function receives the key ID of the temporary public key and the response JSON.
    /// It verifies the response using the attestor's secret key (assuming attestor DID is also
    /// the `server_did` in the config file) and decrypts it with temporary public key
    /// received in previous initiation request.
    /// If the verification is successful, it saves the response to the file and returns
    /// status code OK along with information for the requester on how to proceed.
    pub async fn post_identity_response(
        (Path(key_id), Json(response)): (Path<String>, Json<String>),
        app_state: Arc<AppState>,
    ) -> impl IntoResponse {
        let trustchain_dir: String = std::env::var(TRUSTCHAIN_DATA).unwrap();
        let path = PathBuf::new()
            .join(trustchain_dir)
            .join("attestation_requests")
            .join(&key_id);
        if !path.exists() {
            panic!("Provided attestation request not found. Path does not exist.");
        }
        let mut identity_challenge = IdentityCRChallenge::new()
            .elementwise_deserialize(&path)
            .unwrap()
            .unwrap();
        // get signing key from ION attestor
        let did = app_state.config.server_did.as_ref().unwrap().to_owned();
        let ion_attestor = IONAttestor::new(&did);
        let signing_keys = ion_attestor.signing_keys().unwrap();
        let signing_key_ssi = signing_keys.first().unwrap();
        let signing_key = ssi_to_josekit_jwk(&signing_key_ssi);
        // get temp public key
        let temp_key_path = path.join("temp_p_key.json");
        let file = File::open(&temp_key_path).unwrap();
        let reader = BufReader::new(file);
        let temp_p_key_ssi = serde_json::from_reader(reader)
            .map_err(|_| TrustchainCRError::FailedToDeserialize)
            .unwrap();
        let temp_p_key = ssi_to_josekit_jwk(&temp_p_key_ssi).unwrap();

        // verify response
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
                    data: None
                };
                (StatusCode::OK, respone);
            }
            Err(_) => {
                let response = CustomResponse {
                    message: "Verification failed. Please try again.".to_string(),
                    data: None,
                };
                (StatusCode::BAD_REQUEST, response);
            }
        }
    }

    /// Handles a POST request for content initiation (part 2 attestation CR).
    ///
    /// This function receives the key ID of the temporary public key and the candidate DID.
    /// It resolves the candidate DID and extracts the public signing keys from the document.
    /// It generates a challenge nonce per key and encrypts it with the corresponding
    /// signing key. It then signs (attestor's secret key, assuming attestor DID is also
    /// the `server_did` in the config file) and encrypts (temporary public key)
    /// the challenges and returns them to the requester.
    pub async fn post_content_initiation(
        (Path(key_id), Json(ddid)): (Path<String>, Json<String>),
        app_state: Arc<AppState>,
    ) -> impl IntoResponse {
        let did = app_state.config.server_did.as_ref().unwrap().to_owned();
        // resolve candidate DID
        let result = TrustchainAPI::resolve(&ddid, app_state.verifier.resolver()).await;
        let candidate_doc = match result {
            Ok((_, doc, _)) => doc.unwrap(),
            Err(_) => {
                let respone = CustomResponse {
                    message: "Resolution of candidate DID failed.".to_string(),
                    data: None,
                };
                return (StatusCode::BAD_REQUEST, Json(respone));
            }
        };

        // extract map of keys from candidate document and generate a nonce per key
        let requester_keys = extract_key_ids_and_jwk(&candidate_doc).unwrap();
        let attestor = Entity {};
        let nonces: HashMap<String, Nonce> =
            requester_keys
                .iter()
                .fold(HashMap::new(), |mut acc, (key_id, _)| {
                    acc.insert(String::from(key_id), Nonce::new());
                    acc
                });

        // sign and encrypt nonces to generate challenges
        let challenges = nonces
            .iter()
            .fold(HashMap::new(), |mut acc, (key_id, nonce)| {
                acc.insert(
                    String::from(key_id),
                    attestor
                        .encrypt(
                            &JwtPayload::try_from(nonce).unwrap(),
                            &requester_keys.get(key_id).unwrap(),
                        )
                        .unwrap(),
                );
                acc
            });
        // get public and secret keys
        let path = PathBuf::new()
            .join(std::env::var(TRUSTCHAIN_DATA).unwrap())
            .join("attestation_requests")
            .join(&key_id);
        let identity_cr_initiation = IdentityCRInitiation::new()
            .elementwise_deserialize(&path)
            .unwrap()
            .unwrap();
        let ion_attestor = IONAttestor::new(&did);
        let signing_keys = ion_attestor.signing_keys().unwrap();
        let signing_key_ssi = signing_keys.first().unwrap();
        let signing_key = ssi_to_josekit_jwk(&signing_key_ssi).unwrap();

        // sign and encrypt challenges
        let value: serde_json::Value = serde_json::to_value(challenges).unwrap();
        let mut payload = JwtPayload::new();
        payload.set_claim("challenges", Some(value)).unwrap();
        let signed_encrypted_challenges = attestor.sign_and_encrypt_claim(
            &payload,
            &signing_key,
            &identity_cr_initiation.temp_p_key.unwrap(),
        );

        match signed_encrypted_challenges {
            Ok(signed_encrypted_challenges) => {
                let content_challenge = ContentCRChallenge {
                    content_nonce: Some(nonces),
                    content_challenge_signature: Some(signed_encrypted_challenges.clone()),
                    content_response_signature: None,
                };
                content_challenge.elementwise_serialize(&path).unwrap();
                let response = CustomResponse {
                    message: "Challenges generated successfully.".to_string(),
                    data: Some(signed_encrypted_challenges),
                };
                (StatusCode::OK, Json(response))
            }
            Err(_) => {
                let response = CustomResponse {
                    message: "Failed to generate challenges.".to_string(),
                    data: None,
                };
                (StatusCode::BAD_REQUEST, Json(response))
            }
        }
    }
    /// Handles a POST request for content response.
    ///
    /// This function receives the key ID of the temporary public key and the response JSON.
    /// It verifies the response using the attestor's secret key (assuming attestor DID is also
    /// the `server_did` in the config file) and decrypts it with temporary public key. It then
    /// compares the received nonces with the expected nonces and if they match, it saves the
    /// response to the file and returns status code OK.
    pub async fn post_content_response(
        (Path(key_id), Json(response)): (Path<String>, Json<String>),
        app_state: Arc<AppState>,
    ) -> impl IntoResponse {
        // deserialise expected nonce map
        let path = PathBuf::new()
            .join(std::env::var(TRUSTCHAIN_DATA).unwrap())
            .join("attestation_requests")
            .join(&key_id);
        let identity_cr_initiation = IdentityCRInitiation::new()
            .elementwise_deserialize(&path)
            .unwrap()
            .unwrap();
        let mut content_challenge = ContentCRChallenge::new()
            .elementwise_deserialize(&path)
            .unwrap()
            .unwrap();
        let expected_nonce = content_challenge.content_nonce.clone().unwrap();
        // get signing key from ION attestor
        let did = app_state.config.server_did.as_ref().unwrap().to_owned();
        let ion_attestor = IONAttestor::new(&did);
        let signing_keys = ion_attestor.signing_keys().unwrap();
        let signing_key_ssi = signing_keys.first().unwrap();
        let signing_key = ssi_to_josekit_jwk(&signing_key_ssi).unwrap();

        // decrypt and verify response => nonces map
        let attestor = Entity {};
        let payload = attestor
            .decrypt_and_verify(
                response.clone(),
                &signing_key,
                &identity_cr_initiation.temp_p_key.unwrap(),
            )
            .unwrap();
        let nonces_map: HashMap<String, Nonce> =
            serde_json::from_value(payload.claim("nonces").unwrap().clone()).unwrap();
        // verify nonces
        if nonces_map.eq(&expected_nonce) {
            println!("nonces map: {:?}", nonces_map);
            println!("expected nonces map: {:?}", expected_nonce);
            content_challenge.content_response_signature = Some(response.clone());
            content_challenge.elementwise_serialize(&path).unwrap();
            let response = CustomResponse {
                message: "Attestation request successful.".to_string(),
                data: None,
            };
            return (StatusCode::OK, Json(response));
        }

        let response = CustomResponse {
            message: "Verification failed. Attestation request unsuccessful.".to_string(),
            data: None,
        };
        (StatusCode::BAD_REQUEST, Json(response))
    }
}

/// Generates challenge for part 1 of attestation request (identity challenge-response).
///
/// This function generates a new key pair for the update key and nonce for the challenge.
/// It then adds the update public key and nonce to a payload and signs it with the secret
/// signing key from provided did and encrypts it with the provided temporary public key.
/// It returns a ```CRIdentityChallenge``` struct containing the signed and encrypted challenge
/// payload.
pub fn present_identity_challenge(
    did: &str,
    temp_p_key: &Jwk,
) -> Result<IdentityCRChallenge, TrustchainCRError> {
    // generate nonce and update key
    let nonce = Nonce::new();
    let update_s_key_ssi = generate_key();
    let update_p_key_ssi = update_s_key_ssi.to_public();
    let update_s_key = ssi_to_josekit_jwk(&update_s_key_ssi)
        .map_err(|_| TrustchainCRError::FailedToGenerateKey)?;
    let update_p_key = ssi_to_josekit_jwk(&update_p_key_ssi)
        .map_err(|_| TrustchainCRError::FailedToGenerateKey)?;
    // let update_p_key_string = serde_json::to_string_pretty(&update_p_key)?;

    let mut identity_challenge = IdentityCRChallenge {
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

/// Verifies nonce for part 1 of attestation request (identity challenge-response).
///
/// This function receives a payload provided by requester and the path to the directory
/// where information about the attestation request is stored. It deserialises the expected
/// nonce from the file and compares it with the nonce from the payload.
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
    }

    #[test]
    fn test_verify_nonce() {
        let temp_path = tempdir().unwrap().into_path();
        let expected_nonce = Nonce::from(String::from("test_nonce"));
        let identity_challenge = IdentityCRChallenge {
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
