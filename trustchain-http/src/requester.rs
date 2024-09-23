use std::{collections::HashMap, path::PathBuf};

use josekit::{jwk::Jwk, jwt::JwtPayload};
use serde_json::Value;
use ssi::did::Service;
use trustchain_core::utils::generate_key;
use trustchain_ion::attestor::IONAttestor;

use crate::{
    attestation_encryption_utils::{
        josekit_to_ssi_jwk, ssi_to_josekit_jwk, DecryptVerify, Entity, SignEncrypt,
    },
    attestation_utils::{
        attestation_request_path, matching_endpoint, ContentCRChallenge, ContentCRInitiation,
        ElementwiseSerializeDeserialize, IdentityCRChallenge, IdentityCRInitiation,
        RequesterDetails,
    },
    attestation_utils::{CustomResponse, Nonce, TrustchainCRError},
    ATTESTATION_FRAGMENT,
};

/// Initiates part 1 attestation request (identity challenge-response).
///
/// This function generates a temporary key to use as an identifier throughout the challenge-response process.
/// It prompts the user to provide the organization name and operator name, which are included in the POST request
/// to the endpoint specified in the attestor's DID document.
pub async fn initiate_identity_challenge(
    org_name: &str,
    op_name: &str,
    services: &[Service],
) -> Result<(IdentityCRInitiation, PathBuf), TrustchainCRError> {
    // generate temp key
    let temp_s_key_ssi = generate_key();
    let temp_p_key_ssi = temp_s_key_ssi.to_public();
    let temp_s_key =
        ssi_to_josekit_jwk(&temp_s_key_ssi).map_err(|_| TrustchainCRError::FailedToGenerateKey)?;
    let temp_p_key =
        ssi_to_josekit_jwk(&temp_p_key_ssi).map_err(|_| TrustchainCRError::FailedToGenerateKey)?;

    // make identity_cr_initiation struct
    let requester = RequesterDetails {
        requester_org: org_name.to_owned(),
        operator_name: op_name.to_owned(),
    };
    let mut identity_cr_initiation = IdentityCRInitiation {
        temp_s_key: None,
        temp_p_key: Some(temp_p_key.clone()),
        requester_details: Some(requester.clone()),
    };

    // get endpoint and uri
    let url_path = "/did/attestor/identity/initiate";
    let endpoint = matching_endpoint(services, ATTESTATION_FRAGMENT)?;
    let uri = format!("{}{}", endpoint, url_path);

    // make POST request to endpoint
    let client = reqwest::Client::new();
    let result = client
        .post(uri)
        .json(&identity_cr_initiation)
        .send()
        .await
        .map_err(TrustchainCRError::Reqwest)?;

    if result.status() != 200 {
        return Err(TrustchainCRError::FailedToInitiateCR);
    }
    // create new directory for attestation request
    let path = attestation_request_path(&temp_s_key_ssi.to_public(), "requester")?;
    std::fs::create_dir_all(&path).map_err(|_| TrustchainCRError::FailedAttestationRequest)?;

    // Add secret key to struct
    identity_cr_initiation.temp_s_key = Some(temp_s_key);

    Ok((identity_cr_initiation, path))
}

/// Generates and posts response for part 1 of attesation process (identity challenge-response).
///
/// This function first decrypts and verifies the challenge received from attestor to extract
/// challenge nonce. It then signs the nonce with the requester's temporary secret key and
/// encrypts it with the attestor's public key, before posting the response to the attestor.
/// If post request is successful, the updated ```CRIdentityChallenge``` is returned.
pub async fn identity_response(
    path: &PathBuf,
    services: &[Service],
    attestor_p_key: &Jwk,
) -> Result<IdentityCRChallenge, TrustchainCRError> {
    // deserialise challenge struct from file
    let mut identity_challenge = IdentityCRChallenge::new()
        .elementwise_deserialize(path)?
        .ok_or(TrustchainCRError::FailedToDeserialize)?;
    // get temp secret key from file
    let identity_initiation = IdentityCRInitiation::new()
        .elementwise_deserialize(path)?
        .ok_or(TrustchainCRError::FailedToDeserialize)?;
    let temp_s_key = identity_initiation.temp_s_key()?;
    let temp_s_key_ssi = josekit_to_ssi_jwk(temp_s_key)?;

    // decrypt and verify challenge
    let requester = Entity {};
    let decrypted_verified_payload = requester.decrypt_and_verify(
        identity_challenge
            .identity_challenge_signature
            .clone()
            .ok_or(TrustchainCRError::FieldNotFound)?,
        temp_s_key,
        attestor_p_key,
    )?;
    // sign and encrypt response
    let signed_encrypted_response = requester.sign_and_encrypt_claim(
        &decrypted_verified_payload,
        temp_s_key,
        attestor_p_key,
    )?;
    let key_id = temp_s_key_ssi.to_public().thumbprint()?;
    // get uri for POST request response
    let endpoint = matching_endpoint(services, ATTESTATION_FRAGMENT)?;
    let url_path = "/did/attestor/identity/respond";
    let uri = format!("{}{}/{}", endpoint, url_path, key_id);
    // POST response
    let client = reqwest::Client::new();
    let result = client
        .post(uri)
        .json(&signed_encrypted_response)
        .send()
        .await
        .map_err(TrustchainCRError::Reqwest)?;
    if result.status() != 200 {
        return Err(TrustchainCRError::FailedToRespond(result));
    }
    // extract nonce
    let nonce_str = decrypted_verified_payload
        .claim("identity_nonce")
        .ok_or(TrustchainCRError::ClaimNotFound)?
        .as_str()
        .ok_or(TrustchainCRError::FailedToConvertToStr(
            // Unwrap: not None since error would have propagated above if None
            decrypted_verified_payload
                .claim("identity_nonce")
                .unwrap()
                .clone(),
        ))?;
    let nonce = Nonce::from(String::from(nonce_str));
    // update struct
    identity_challenge.update_p_key = Some(attestor_p_key.clone());
    identity_challenge.identity_nonce = Some(nonce);
    identity_challenge.identity_response_signature = Some(signed_encrypted_response);

    Ok(identity_challenge)
}

/// Initiates part 2 attestation request (content challenge-response).
///
/// This function posts the to be attested to candidate DID (dDID) to the attestor's endpoint.
/// If the post request is successful, the response body contains the signed and encrypted
/// challenge payload with a hashmap that contains an encrypted nonce per signing key.
/// The response to the challenge is generated and posted to the attestor's endpoint.
/// If the post request and the verification of the response are successful, the
/// ```ContentCRInitiation``` and ```CRContentChallenge``` structs are returned.
pub async fn initiate_content_challenge(
    path: &PathBuf,
    ddid: &str,
    services: &[Service],
    attestor_p_key: &Jwk,
) -> Result<(ContentCRInitiation, ContentCRChallenge), TrustchainCRError> {
    // deserialise identity_cr_initiation and get key id
    let identity_cr_initiation = IdentityCRInitiation::new()
        .elementwise_deserialize(path)?
        .ok_or(TrustchainCRError::FailedToDeserialize)?;
    let temp_s_key_ssi = josekit_to_ssi_jwk(&identity_cr_initiation.temp_s_key().cloned()?)?;
    let key_id = temp_s_key_ssi.to_public().thumbprint()?;

    let content_cr_initiation = ContentCRInitiation {
        requester_did: Some(ddid.to_owned()),
    };
    // get uri for POST request response
    let endpoint = matching_endpoint(services, ATTESTATION_FRAGMENT)?;
    let url_path = "/did/attestor/content/initiate";
    let uri = format!("{}{}/{}", endpoint, url_path, key_id);
    // make POST request to endpoint
    let client = reqwest::Client::new();
    let result = client
        .post(uri)
        .json(&ddid)
        .send()
        .await
        .map_err(TrustchainCRError::Reqwest)?;
    if result.status() != 200 {
        println!("Status code: {}", result.status());
        return Err(TrustchainCRError::FailedToRespond(result));
    }

    let response_body: CustomResponse = result.json().await.map_err(TrustchainCRError::Reqwest)?;
    let signed_encrypted_challenge = response_body
        .data
        .ok_or(TrustchainCRError::ResponseMustContainData)?;

    // response
    let (nonces, response) = content_response(
        path,
        &signed_encrypted_challenge.to_string(),
        services,
        attestor_p_key.clone(),
        ddid,
    )
    .await?;
    let content_challenge = ContentCRChallenge {
        content_nonce: Some(nonces),
        content_challenge_signature: Some(signed_encrypted_challenge.to_string()),
        content_response_signature: Some(response),
    };
    Ok((content_cr_initiation, content_challenge))
}

/// Generates the response for the content challenge-response process and makes a POST request to
/// the attestor endpoint.
///
/// This function first decrypts (temporary secret key) and verifies (attestor's public key) the
/// challenge received from attestor to extract challenge nonces. It then decrypts each nonce with
/// the corresponding signing key from the requestor's candidate DID (dDID) document, before
/// posting the signed (temporary secret key) and encrypted (attestor's public key) response to
/// the attestor's endpoint.
/// If successful, the nonces and the (signed and encrypted) response are returned.
pub async fn content_response(
    path: &PathBuf,
    challenge: &str,
    services: &[Service],
    attestor_p_key: Jwk,
    ddid: &str,
) -> Result<(HashMap<String, Nonce>, String), TrustchainCRError> {
    // get keys
    let identity_initiation = IdentityCRInitiation::new()
        .elementwise_deserialize(path)?
        .ok_or(TrustchainCRError::FailedToDeserialize)?;
    let temp_s_key = identity_initiation.temp_s_key()?;
    let temp_s_key_ssi = josekit_to_ssi_jwk(temp_s_key)?;
    // get endpoint
    let key_id = temp_s_key_ssi.to_public().thumbprint()?;
    let endpoint = matching_endpoint(services, ATTESTATION_FRAGMENT)?;
    let url_path = "/did/attestor/content/respond";
    let uri = format!("{}{}/{}", endpoint, url_path, key_id);

    // decrypt and verify payload
    let requester = Entity {};
    let decrypted_verified_payload =
        requester.decrypt_and_verify(challenge.to_owned(), temp_s_key, &attestor_p_key)?;
    // extract map with decrypted nonces from payload and decrypt each nonce
    let challenges_map: HashMap<String, String> = serde_json::from_value(
        decrypted_verified_payload
            .claim("challenges")
            .ok_or(TrustchainCRError::ClaimNotFound)?
            .clone(),
    )?;

    // keymap with requester secret keys
    let ion_attestor = IONAttestor::new(ddid);
    let signing_keys = ion_attestor.signing_keys()?;
    // iterate over all keys, convert to Jwk (josekit)
    let mut signing_keys_map: HashMap<String, Jwk> = HashMap::new();
    for key in signing_keys {
        let key_id = key.thumbprint()?;
        let jwk = ssi_to_josekit_jwk(&key)?;
        signing_keys_map.insert(key_id, jwk);
    }

    // TODO: make functional version work with error propagation for HashMap fold
    // let signing_keys_map = signing_keys
    //     .into_iter()
    //     .fold(HashMap::new(), |mut acc, key| {
    //         let key_id = key.thumbprint().unwrap();
    //         let jwk = ssi_to_josekit_jwk(&key);
    //         acc.insert(key_id, jwk);
    //         acc
    //     });

    let mut decrypted_nonces: HashMap<String, Nonce> = HashMap::new();
    for (key_id, nonce) in challenges_map.iter() {
        let payload = requester.decrypt(
            &Value::from(nonce.clone()),
            signing_keys_map
                .get(key_id)
                .ok_or(TrustchainCRError::KeyNotFound)?,
        )?;
        decrypted_nonces.insert(
            String::from(key_id),
            Nonce::from(
                payload
                    .claim("nonce")
                    .ok_or(TrustchainCRError::ClaimNotFound)?
                    .as_str()
                    .ok_or(TrustchainCRError::FailedToConvertToStr(
                        // Unwrap: not None since error would have propagated above if None
                        payload.claim("nonce").unwrap().clone(),
                    ))?
                    .to_string(),
            ),
        );
    }

    // sign and encrypt response
    let value: serde_json::Value = serde_json::to_value(&decrypted_nonces)?;
    let mut payload = JwtPayload::new();
    payload.set_claim("nonces", Some(value))?;
    let signed_encrypted_response =
        requester.sign_and_encrypt_claim(&payload, temp_s_key, &attestor_p_key)?;
    // post response to endpoint
    let client = reqwest::Client::new();
    let result = client
        .post(uri)
        .json(&signed_encrypted_response)
        .send()
        .await
        .map_err(TrustchainCRError::Reqwest)?;
    if result.status() != 200 {
        println!("Status code: {}", result.status());
        return Err(TrustchainCRError::FailedToRespond(result));
    }
    Ok((decrypted_nonces, signed_encrypted_response))
}
