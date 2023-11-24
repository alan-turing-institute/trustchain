use std::{collections::HashMap, path::PathBuf};

use josekit::{jwk::Jwk, jwt::JwtPayload};
use serde_json::Value;
use ssi::{
    did::{Service, ServiceEndpoint},
    vc::OneOrMany,
};
use trustchain_core::utils::generate_key;
use trustchain_ion::attestor::IONAttestor;

use crate::{
    attestation_encryption_utils::{
        josekit_to_ssi_jwk, ssi_to_josekit_jwk, DecryptVerify, Entity, SignEncrypt,
    },
    attestation_utils::{
        attestation_request_path, matching_endpoint, CRContentChallenge, CRIdentityChallenge,
        ContentCRInitiation, ElementwiseSerializeDeserialize, IdentityCRInitiation,
        RequesterDetails,
    },
    attestation_utils::{Nonce, TrustchainCRError},
};

/// Initiates the identity challenge-response process by sending a POST request to the attestor endpoint.
///
/// This function generates a temporary key to use as an identifier throughout the challenge-response process.
/// It prompts the user to provide the organization name and operator name, which are included in the POST request
/// to the endpoint specified in the attestor's DID document.
pub async fn initiate_identity_challenge(
    org_name: String,
    op_name: String,
    services: &Vec<Service>,
) -> Result<(), TrustchainCRError> {
    // generate temp key
    let temp_s_key_ssi = generate_key();
    let temp_p_key_ssi = temp_s_key_ssi.to_public();
    let temp_s_key =
        ssi_to_josekit_jwk(&temp_s_key_ssi).map_err(|_| TrustchainCRError::FailedToGenerateKey)?;
    let temp_p_key =
        ssi_to_josekit_jwk(&temp_p_key_ssi).map_err(|_| TrustchainCRError::FailedToGenerateKey)?;

    // make identity_cr_initiation struct
    let requester = RequesterDetails {
        requester_org: org_name,
        operator_name: op_name,
    };
    let mut identity_cr_initiation = IdentityCRInitiation {
        temp_s_key: None,
        temp_p_key: Some(temp_p_key.clone()),
        requester_details: Some(requester.clone()),
    };

    // get endpoint and uri
    let url_path = "/did/attestor/identity/initiate";
    let endpoint = matching_endpoint(services, "AttestationEndpoint").unwrap();
    let uri = format!("{}{}", endpoint, url_path);

    // make POST request to endpoint
    let client = reqwest::Client::new();
    let result = client
        .post(uri)
        .json(&identity_cr_initiation)
        .send()
        .await
        .map_err(|err| TrustchainCRError::Reqwest(err))?;

    println!("Status code: {}", result.status());
    if result.status() != 200 {
        return Err(TrustchainCRError::FailedToInitiateCR);
    }
    // create new directory
    let directory = attestation_request_path(&temp_s_key_ssi.to_public())?;
    std::fs::create_dir_all(&directory).map_err(|_| TrustchainCRError::FailedAttestationRequest)?;

    // serialise identity_cr_initiation struct to file
    identity_cr_initiation.temp_s_key = Some(temp_s_key);
    identity_cr_initiation.elementwise_serialize(&directory)?;
    println!("Successfully initiated attestation request.");
    println!("You will receive more information on the challenge-response process via alternative communication channel.");
    Ok(())
}

/// Generates the response for the identity challenge-response process and makes a POST request to the attestor endpoint.
///
/// This function first decrypts and verifies the challenge received from attestor to extract challenge nonce.
/// It then signs the nonce with the requester's temporary secret key and encrypts it with the attestor's public key,
/// before posting the response to the attestor's endpoint, using the provided url path.  
pub async fn identity_response(
    path: PathBuf,
    services: Vec<Service>,
    attestor_p_key: Jwk,
) -> Result<(), TrustchainCRError> {
    // deserialise challenge struct from file
    let result = CRIdentityChallenge::new().elementwise_deserialize(&path);
    let mut identity_challenge = result.unwrap().unwrap();
    let identity_initiation = IdentityCRInitiation::new().elementwise_deserialize(&path);
    let temp_s_key = identity_initiation.unwrap().unwrap().temp_s_key.unwrap();
    let temp_s_key_ssi = josekit_to_ssi_jwk(&temp_s_key).unwrap();

    // decrypt and verify challenge
    let requester = Entity {};
    let decrypted_verified_payload = requester
        .decrypt_and_verify(
            identity_challenge
                .identity_challenge_signature
                .clone()
                .unwrap(),
            &temp_s_key,
            &attestor_p_key,
        )
        .unwrap();
    // sign and encrypt response
    let signed_encrypted_response = requester
        .sign_and_encrypt_claim(&decrypted_verified_payload, &temp_s_key, &attestor_p_key)
        .unwrap();
    println!(
        "Signed and encrypted response: {:?}",
        signed_encrypted_response
    );
    let key_id = temp_s_key_ssi.to_public().thumbprint().unwrap();
    // get uri for POST request response
    let endpoint = &services.first().unwrap().service_endpoint;
    let endpoint = match endpoint {
        Some(OneOrMany::One(ServiceEndpoint::URI(uri))) => uri,

        _ => Err(TrustchainCRError::InvalidServiceEndpoint)?,
    };
    let url_path = "/did/attestor/identity/respond";
    let uri = format!("{}{}/{}", endpoint, url_path, key_id);
    // POST response
    let client = reqwest::Client::new();
    let result = client
        .post(uri)
        .json(&signed_encrypted_response)
        .send()
        .await
        .map_err(|err| TrustchainCRError::Reqwest(err))?;
    println!("Status code: {}", result.status());
    if result.status() != 200 {
        return Err(TrustchainCRError::FailedToRespond);
    }
    // extract nonce
    let nonce_str = decrypted_verified_payload
        .claim("identity_nonce")
        .unwrap()
        .as_str()
        .unwrap();
    let nonce = Nonce::from(String::from(nonce_str));
    // update struct
    identity_challenge.update_p_key = Some(attestor_p_key);
    identity_challenge.identity_nonce = Some(nonce);
    identity_challenge.identity_response_signature = Some(signed_encrypted_response);
    // serialise
    identity_challenge.elementwise_serialize(&path)?;
    Ok(())
}

/// Initiates the content challenge-response process by sending a POST request to the attestor endpoint.
///
/// This function makes a POST request with the candidate DID (dDID) to the attestor endpoint, using the url path received during
/// the identity challenge-response.
pub async fn initiate_content_challenge(
    path: PathBuf,
    ddid: &String,
    services: &Vec<Service>,
) -> Result<(), TrustchainCRError> {
    // deserialise identity_cr_initiation and get key id
    let identity_cr_initiation = IdentityCRInitiation::new()
        .elementwise_deserialize(&path)
        .unwrap()
        .unwrap();
    let temp_s_key_ssi = josekit_to_ssi_jwk(&identity_cr_initiation.temp_s_key.unwrap()).unwrap();
    let key_id = temp_s_key_ssi.to_public().thumbprint().unwrap();

    let content_cr_initiation = ContentCRInitiation {
        requester_did: Some(ddid.clone()),
    };

    // get uri for POST request response
    let endpoint = &services.first().unwrap().service_endpoint;
    let endpoint = match endpoint {
        Some(OneOrMany::One(ServiceEndpoint::URI(uri))) => uri,

        _ => Err(TrustchainCRError::InvalidServiceEndpoint)?,
    };
    let url_path = "/did/attestor/content/initiate";
    let uri = format!("{}{}/{}", endpoint, url_path, key_id);
    println!("URI: {}", uri);
    // make POST request to endpoint
    let client = reqwest::Client::new();
    let result = client
        .post(uri)
        .json(&ddid)
        .send()
        .await
        .map_err(|err| TrustchainCRError::Reqwest(err))?;

    if result.status() != 200 {
        println!("Status code: {}", result.status());
        return Err(TrustchainCRError::FailedToInitiateCR);
    }

    // serialise struct to file
    content_cr_initiation.elementwise_serialize(&path)?;
    Ok(())
}

/// Generates the response for the content challenge-response process and makes a POST request to
/// the attestor endpoint.
///
/// This function first decrypts (temporary secret key) and verifies (attestor's public key) the
/// challenge received from attestor to extract challenge nonces. It then decrypts each nonce with the corresponding
/// signing key from the requestor's candidate DID (dDID) document, before posting the signed (temporary secret key)
/// and encrypted (attestor's public key) response to the attestor's endpoint, using the provided url path.
pub async fn content_response(
    path: PathBuf,
    services: Vec<Service>,
    attestor_p_key: Jwk,
    ddid: &String,
) -> Result<(), TrustchainCRError> {
    // deserialise challenge struct from file
    let result = CRContentChallenge::new().elementwise_deserialize(&path);
    let mut content_challenge = result.unwrap().unwrap();
    let challenge = content_challenge
        .content_challenge_signature
        .clone()
        .unwrap();

    // get keys
    let identity_initiation = IdentityCRInitiation::new().elementwise_deserialize(&path);
    let temp_s_key = identity_initiation.unwrap().unwrap().temp_s_key.unwrap();
    let temp_s_key_ssi = josekit_to_ssi_jwk(&temp_s_key).unwrap();
    // get endpoint
    let key_id = temp_s_key_ssi.to_public().thumbprint().unwrap();
    let endpoint = &services.first().unwrap().service_endpoint;
    let endpoint = match endpoint {
        Some(OneOrMany::One(ServiceEndpoint::URI(uri))) => uri,

        _ => Err(TrustchainCRError::InvalidServiceEndpoint)?,
    };
    let url_path = "/did/attestor/content/respond";
    let uri = format!("{}{}/{}", endpoint, url_path, key_id);

    // decrypt and verify payload
    let requester = Entity {};
    let decrypted_verified_payload = requester
        .decrypt_and_verify(challenge, &temp_s_key, &attestor_p_key)
        .unwrap();
    // extract map with decrypted nonces from payload and decrypt each nonce
    let challenges_map: HashMap<String, String> = serde_json::from_value(
        decrypted_verified_payload
            .claim("challenges")
            .unwrap()
            .clone(),
    )
    .unwrap();

    // keymap with requester secret keys
    let ion_attestor = IONAttestor::new(&ddid);
    let signing_keys = ion_attestor.signing_keys().unwrap();
    // iterate over all keys, convert to Jwk (josekit) -> TODO: functional
    let mut signing_keys_map: HashMap<String, Jwk> = HashMap::new();
    for key in signing_keys {
        let key_id = key.thumbprint().unwrap();
        let jwk = ssi_to_josekit_jwk(&key).unwrap();
        signing_keys_map.insert(key_id, jwk);
    }

    let decrypted_nonces: HashMap<String, String> =
        challenges_map
            .iter()
            .fold(HashMap::new(), |mut acc, (key_id, nonce)| {
                acc.insert(
                    String::from(key_id),
                    requester
                        .decrypt(
                            &Some(Value::from(nonce.clone())).unwrap(),
                            signing_keys_map.get(key_id).unwrap(),
                        )
                        .unwrap()
                        .claim("nonce")
                        .unwrap()
                        .as_str()
                        .unwrap()
                        .to_string(),
                );

                acc
            });
    // sign and encrypt response
    let value: serde_json::Value = serde_json::to_value(decrypted_nonces).unwrap();
    let mut payload = JwtPayload::new();
    payload.set_claim("nonces", Some(value)).unwrap();
    let signed_encrypted_response = requester
        .sign_and_encrypt_claim(&payload, &temp_s_key, &attestor_p_key)
        .unwrap();
    // post respone to endpoint
    let client = reqwest::Client::new();
    let result = client
        .post(uri)
        .json(&signed_encrypted_response)
        .send()
        .await
        .map_err(|err| TrustchainCRError::Reqwest(err))?;
    if result.status() != 200 {
        println!("Status code: {}", result.status());
        return Err(TrustchainCRError::FailedToRespond);
    }
    // serialise
    content_challenge.content_response_signature = Some(signed_encrypted_response);
    content_challenge.elementwise_serialize(&path)?;
    Ok(())
}
