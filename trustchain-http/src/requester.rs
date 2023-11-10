use josekit::jwt::JwtPayload;
use ssi::did::Service;
use trustchain_core::utils::generate_key;

use crate::{
    attestation_encryption_utils::{ssi_to_josekit_jwk, Entity},
    attestation_utils::TrustchainCRError,
    attestation_utils::{
        attestation_request_path, matching_endpoint, CRIdentityChallenge,
        ElementwiseSerializeDeserialize, IdentityCRInitiation, RequesterDetails,
    },
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

    // let identity_cr_initiation_attestor = IdentityCRInitiation {
    //     temp_p_key: Some(temp_p_key),
    //     temp_s_key: None,
    //     requester_details: Some(requester),
    // };

    // extract URI from service endpoint
    println!("Services: {:?}", services);
    let uri = matching_endpoint(services, "Trustchain").unwrap(); // this is just to make current example work
                                                                  // let uri = matching_endpoint(services, "identity-cr").unwrap(); // TODO: use this one once we have example published

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

pub fn identity_response(
    challenge_payload: JwtPayload,
    identity_initiation: IdentityCRInitiation,
    endpoint: String,
    upstream_p_key: String,
) -> Result<(), TrustchainCRError> {
    // TODO: get all required keys: temp_s_key and public key upstream
    // TODO: decrypt and verify challenge
    let requester = Entity {};
    // let decrypted_verified_challenge = requester
    //     .decrypt_and_verify(challenge_payload, &temp_s_key, &upstream_p_key)
    //     .unwrap();
    // TODO: sign and encrypt response
    // TODO: send response to endpoint
    todo!("Implement identity response")
}
