use std::{fs::File, io::BufReader, path::PathBuf};

use josekit::jwk::Jwk;
use ssi::{
    did::{Service, ServiceEndpoint},
    vc::OneOrMany,
};
use trustchain_core::utils::generate_key;

use crate::{
    attestation_encryption_utils::{
        josekit_to_ssi_jwk, ssi_to_josekit_jwk, DecryptVerify, Entity, SignEncrypt,
    },
    attestation_utils::{
        attestation_request_path, matching_endpoint, CRIdentityChallenge,
        ElementwiseSerializeDeserialize, IdentityCRInitiation, RequesterDetails,
    },
    attestation_utils::{Nonce, TrustchainCRError},
};

/// Initiates the identity challenge-response process by sending a POST request to the upstream endpoint.
///
/// This function generates a temporary key to use as an identifier throughout the challenge-response process.
/// It prompts the user to provide the organization name and operator name, which are included in the POST request
/// to the endpoint specified in the upstream's DID document.
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

    // extract URI from service endpoint
    // TODO: this is just to make current example work
    let uri = matching_endpoint(services, "Trustchain").unwrap();

    // make POST request to endpoint
    let client = reqwest::Client::new();
    let result = client
        .post(uri)
        .json(&identity_cr_initiation)
        .send()
        .await
        .map_err(|err| TrustchainCRError::Reqwest(err))?;

    if result.status() != 200 {
        println!("Status code: {}", result.status());
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

pub async fn identity_response(
    path: PathBuf,
    services: Vec<Service>,
    url_path: String,
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
    let uri = format!("{}{}{}", endpoint, url_path, key_id);
    // POST response
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
