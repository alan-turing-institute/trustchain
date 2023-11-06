use ssi::did::Service;
use trustchain_core::utils::generate_key;

use crate::{
    attestation_encryption_utils::ssi_to_josekit_jwk,
    attestation_utils::TrustchainCRError,
    attestation_utils::{
        attestation_request_path, matching_endpoint, ElementwiseSerializeDeserialize,
        IdentityCRInitiation, RequesterDetails,
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
    let temp_s_key =
        ssi_to_josekit_jwk(&temp_s_key_ssi).map_err(|_| TrustchainCRError::FailedToGenerateKey)?;

    // make identity_cr_initiation struct
    let requester = RequesterDetails {
        requester_org: org_name,
        operator_name: op_name,
    };
    let identity_cr_initiation = IdentityCRInitiation {
        temp_p_key: temp_s_key.to_public_key().ok(),
        requester_details: Some(requester),
    };
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

    // serialise identity_cr_initiation
    identity_cr_initiation.elementwise_serialize(&directory)?;
    println!("Successfully initiated attestation request.");
    println!("You will receive more information on the challenge-response process via alternative communication channel.");
    Ok(())
}
