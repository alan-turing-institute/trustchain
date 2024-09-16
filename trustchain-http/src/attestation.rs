use std::{collections::HashMap, fs::File, path::PathBuf};

use josekit::{jwk::Jwk, jwt::JwtPayload};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use ssi::jwk::JWK;
use trustchain_core::utils::generate_key;
use trustchain_ion::attestor::IONAttestor;

use crate::{
    attestation_encryption_utils::{
        josekit_to_ssi_jwk, ssi_to_josekit_jwk, DecryptVerify, Entity, SignEncrypt,
    },
    attestation_utils::{
        attestation_endpoint, attestation_request_path, get_services, matching_endpoint,
        CustomResponse, ElementwiseSerializeDeserialize, IdentityCRChallenge, Nonce,
        RequesterDetails, TrustchainCRError,
    },
    attestor::{first_signing_key, present_identity_challenge},
    requester, ATTESTATION_FRAGMENT,
};

/// Generic types for Attestation type state pattern.
struct NotStarted;
struct Initiated;
struct IdentityChallengeShared;
struct IdentityResponseShared;
struct ContentChallengeShared;
struct ContentResponseShared;
struct ContentChallengeComplete;
struct Complete; // Includes check that dDID is published?

#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, Clone)]
/// Type for storing details of part one (identity challenge) of the challenge-response process.
pub struct IdentityChallengePayload {
    pub update_p_key: Jwk,
    pub identity_nonce: Nonce, // make own Nonce type
}

#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, Clone)]
/// Type for storing details of part one (identity challenge) of the challenge-response process.
pub struct IdentityChallenge {
    pub payload: IdentityChallengePayload,
    pub identity_challenge_signature: String,
    pub identity_response_signature: Option<String>,
}

/// Data shared by the requester & attestor pertaining to the dDID attestation process.
/// The generic type `State` is used to track the progress.
#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, Clone)]
struct Attestation<State = NotStarted> {
    requester_details: RequesterDetails,

    // Temporary keys for use during the challenge-response process.
    // The SSI keys (type JWK) are generated independently and used in the data directory path.
    // The josekit keys (type Jwk) are derived from the SSI keys and used for communication between requester and attestor.
    temp_p_key_ssi: JWK,
    temp_p_key: Jwk,

    udid: Option<String>,

    update_p_key: Option<Jwk>,
    identity_nonce: Option<Nonce>,

    identity_challenge_signature: Option<String>,
    identity_response_signature: Option<String>,

    ddid: Option<String>,

    content_nonces: Option<HashMap<String, Nonce>>,

    content_challenge_signature: Option<String>,
    content_response_signature: Option<String>,

    state: std::marker::PhantomData<State>,
    // TODO: consider using a non-zero size State type, then implement a get_state() method
    // in impl<Stat> Attestation<State> {} that returns the state of the attestation process.
    // state: State,
}

/// State of the Attestion before the process has been initiated.
impl Attestation<NotStarted> {
    // Requester side.
    pub fn new(
        requester_details: RequesterDetails,
    ) -> Result<Attestation<NotStarted>, TrustchainCRError> {
        // Generate temporary keys for use throughout the attestion process.
        let temp_s_key_ssi = generate_key();
        let temp_p_key_ssi = temp_s_key_ssi.to_public();
        let temp_s_key = ssi_to_josekit_jwk(&temp_s_key_ssi)
            .map_err(|_| TrustchainCRError::FailedToGenerateKey)?;
        let temp_p_key = ssi_to_josekit_jwk(&temp_p_key_ssi)
            .map_err(|_| TrustchainCRError::FailedToGenerateKey)?;

        // TODO: save the temp_s_key_ssi and temp_s_key (on the requester side) separately from the
        // Attestion data structure (which only contains data *shared* by both sides.)

        Ok(Attestation {
            requester_details,
            temp_p_key,
            // temp_s_key,
            temp_p_key_ssi,
            // temp_s_key_ssi,
            udid: None,
            update_p_key: None,
            // update_s_key: None,
            identity_nonce: None,
            identity_challenge_signature: None,
            identity_response_signature: None,
            ddid: None,
            content_nonces: None,
            content_challenge_signature: None,
            content_response_signature: None,
            state: std::marker::PhantomData::<NotStarted>,
        })
    }

    // Requester side.
    // TODO: consider replacing services argument with the upstream DID (from which the relevant
    // services can be obtained).
    /// Initiates the attestation process by sending a request from the requester to the attestor.
    ///
    /// ends the requester's details (organization name and operator name) and the temporary public
    /// key in a POST request to the endpoint specified in the attestor's DID document.
    pub async fn initiate_attestation_request(
        self,
        udid: &str,
    ) -> Result<Attestation<Initiated>, TrustchainCRError> {
        // Get endpoint and URI. TODO: use URI type.
        let url_path = "/did/attestor/identity/initiate";
        let endpoint = attestation_endpoint(&udid)?;
        let uri = format!("{}{}", endpoint, url_path);

        let attestation_request = AttestationRequest {
            temp_p_key: self.temp_p_key.clone(),
            requester_details: self.requester_details(),
        };

        // Make POST request to endpoint.
        let client = reqwest::Client::new();
        let result = client
            .post(uri)
            .json(&attestation_request)
            .send()
            .await
            .map_err(|err| TrustchainCRError::Reqwest(err))?;

        if result.status() != 200 {
            return Err(TrustchainCRError::FailedToInitiateCR);
        }

        // Create a new directory to store data related to this attestation request.
        let path = self.attestation_request_path("requester")?;
        std::fs::create_dir_all(&path).map_err(|_| TrustchainCRError::FailedAttestationRequest)?;

        let updated_attestation = Attestation {
            requester_details: self.requester_details,
            temp_p_key_ssi: self.temp_p_key_ssi,
            temp_p_key: self.temp_p_key,
            udid: Some(udid.to_string()),
            update_p_key: None,
            identity_nonce: None,
            identity_challenge_signature: None,
            identity_response_signature: None,
            ddid: None,
            content_nonces: None,
            content_challenge_signature: None,
            content_response_signature: None,
            state: std::marker::PhantomData::<Initiated>,
        };

        // TODO: serialise the initiated attestation (to update the persistent state on the requester side).

        Ok(updated_attestation)
    }
}

// // TODO: something like this, but without needing an Attestation instance before deserialisation:
// impl ElementwiseSerializeDeserialize for Attestation<NotStarted> {
//     fn elementwise_deserialize(self, path: &PathBuf) -> Result<Option<Self>, TrustchainCRError>
//     where
//         Self: Sized,
//     {
//         // Deserialise the data available in the NotStarted state.
//         todo!();

//         // Requester details:

//         // Temp public key:

//         // Temp SSI public key:
//     }
// }

/// State of the Attestation after the requester has made the initial request.
impl Attestation<Initiated> {
    // Static deserialisation constructor.
    pub fn deserialise(path: &PathBuf) -> Result<Attestation<Initiated>, TrustchainCRError> {
        todo!();

        // Read these parameters from file:
        // requester_details: RequesterDetails,
        // temp_p_key_ssi: JWK,
        // temp_p_key: Jwk,
        // udid: String,

        // // Return the Initiated Attestation.
        // Ok(Attestation {
        //     requester_details: self.requester_details,
        //     temp_p_key_ssi: self.temp_p_key_ssi,
        //     temp_p_key: self.temp_p_key,
        //     udid: Some(udid.to_string()),
        //     update_p_key: None,
        //     identity_nonce: None,
        //     identity_challenge_signature: None,
        //     identity_response_signature: None,
        //     ddid: None,
        //     content_nonces: None,
        //     content_challenge_signature: None,
        //     content_response_signature: None,
        //     state: std::marker::PhantomData::<Initiated>,
        // })
    }

    // Attestor side.
    pub fn send_identity_challenge(
        self,
    ) -> Result<Attestation<IdentityChallengeShared>, TrustchainCRError> {
        let udid = &self.udid.expect("Some value guaranteed by state.");
        // let identity_challenge = present_identity_challenge(udid, &self.temp_p_key);

        // Generate challenge nonce and update keys.
        let identity_nonce = Nonce::new();
        let update_s_key_ssi = generate_key();
        let update_p_key_ssi = update_s_key_ssi.to_public();
        let update_s_key = ssi_to_josekit_jwk(&update_s_key_ssi)
            .map_err(|_| TrustchainCRError::FailedToGenerateKey)?;
        let update_p_key = ssi_to_josekit_jwk(&update_p_key_ssi)
            .map_err(|_| TrustchainCRError::FailedToGenerateKey)?;

        // TODO: save the update_s_key_ssi (on the attestor side) separately from the
        // Attestion data structure (which only contains data *shared* by both sides.)

        // Make the payload.
        let mut identity_challenge_payload = IdentityChallengePayload {
            update_p_key: update_p_key.clone(),
            // update_s_key: Some(update_s_key.clone()),
            identity_nonce: identity_nonce.clone(),
        };
        let payload = JwtPayload::try_from(&identity_challenge_payload)?;

        // Get the attestor's signing key.
        let ion_attestor = IONAttestor::new(udid);
        let signing_keys = ion_attestor.signing_keys()?;
        let signing_key_ssi = first_signing_key(&signing_keys, udid)?;
        let signing_key = ssi_to_josekit_jwk(signing_key_ssi)
            .map_err(|_| TrustchainCRError::FailedToGenerateKey)?;

        // Sign (with uDID key) and encrypt (with temp_p_key) the payload.
        let attestor = Entity {};
        let signed_encrypted_challenge =
            attestor.sign_and_encrypt_claim(&payload, &signing_key, &self.temp_p_key);

        // Add the attestor's signature to the identity challenge.
        let identity_challenge_signature = signed_encrypted_challenge?;
        // identity_challenge.identity_challenge_signature = identity_challenge_signature.clone();
        let identity_challenge = IdentityChallenge {
            payload: identity_challenge_payload,
            identity_challenge_signature: identity_challenge_signature.clone(),
            identity_response_signature: None,
        };

        // TODO: SEND THE IDENTITY CHALLENGE TO THE REQUESTER *OUT-OF-BAND*.

        let updated_attestation = Attestation {
            requester_details: self.requester_details,
            temp_p_key_ssi: self.temp_p_key_ssi,
            temp_p_key: self.temp_p_key,
            udid: Some(udid.to_string()),
            update_p_key: Some(update_p_key),
            identity_nonce: Some(identity_nonce),
            identity_challenge_signature: Some(identity_challenge_signature),
            identity_response_signature: None,
            ddid: None,
            content_nonces: None,
            content_challenge_signature: None,
            content_response_signature: None,
            state: std::marker::PhantomData::<IdentityChallengeShared>,
        };

        // TODO: serialise the updated attestation (to update the persistent state on the attestor side).

        Ok(updated_attestation)
    }

    // Requester side.
    /// Updates state by admitting the identity challenge (that was received *out-of_band* from the attestor).
    pub fn admit_identity_challenge(
        self,
        // identity_challenge: IdentityChallenge,
    ) -> Result<Attestation<IdentityChallengeShared>, TrustchainCRError> {
        // TODO: Deserialise the identity challenge from the attestation_request_path.
        let identity_challenge = self.read_identity_challenge()?;

        // TODO: Decrypt the identity challenge using the temp_s_key.

        // TODO: Check the attestor's signature on the identity challenge using their public key
        // from the uDID.

        let updated_attestation = Attestation {
            requester_details: self.requester_details,
            temp_p_key_ssi: self.temp_p_key_ssi,
            temp_p_key: self.temp_p_key,
            udid: self.udid,
            update_p_key: Some(identity_challenge.payload.update_p_key),
            identity_nonce: Some(identity_challenge.payload.identity_nonce),
            identity_challenge_signature: Some(identity_challenge.identity_challenge_signature),
            identity_response_signature: None,
            ddid: None,
            content_nonces: None,
            content_challenge_signature: None,
            content_response_signature: None,
            state: std::marker::PhantomData::<IdentityChallengeShared>,
        };

        // TODO: serialise the updated attestation (to update the persistent state on the requester side).

        Ok(updated_attestation)
    }

    // Requester side.
    /// Reads the identity challenge from disk. Returns an error if called by the attestor.
    fn read_identity_challenge(&self) -> Result<IdentityChallenge, TrustchainCRError> {
        todo!()
    }
}

// Here we assume the Attestation has been deserialised by the requester in the IdentityChallengeShared state
// (i.e. after admitting the identity challenge that was sent *out-of-band* by the attestor).
/// State of the Attestation after the identity challenge has been shared by attestor and received
/// (and admitted) by the requester.
impl Attestation<IdentityChallengeShared> {
    // Static deserialisation constructor.
    pub fn deserialise(
        path: &PathBuf,
    ) -> Result<Attestation<IdentityChallengeShared>, TrustchainCRError> {
        todo!();

        // Read these parameters from file:
        // requester_details: RequesterDetails,
        // temp_p_key_ssi: JWK,
        // temp_p_key: Jwk,
        // udid: String,
        // update_p_key: Jwk,
        // identity_nonce: Nonce,
        // identity_challenge_signature: String,

        // // Return the Attestation in state IdentityChallengeShared.
        // Ok(Attestation {
        //     requester_details: self.requester_details,
        //     temp_p_key_ssi: self.temp_p_key_ssi,
        //     temp_p_key: self.temp_p_key,
        //     udid: Some(udid.to_string()),
        //     update_p_key: Some(update_p_key),
        //     identity_nonce: Some(identity_nonce),
        //     identity_challenge_signature: Some(identity_challenge_signature),
        //     identity_response_signature: None,
        //     ddid: None,
        //     content_nonces: None,
        //     content_challenge_signature: None,
        //     content_response_signature: None,
        //     state: std::marker::PhantomData::<IdentityChallengeShared>,
        // })
    }

    // Requester side.
    /// Generates and posts response for part 1 of attesation process (identity challenge-response).
    ///
    /// This function first decrypts and verifies the challenge received from attestor to extract
    /// challenge nonce. It then signs the nonce with the requester's temporary secret key and
    /// encrypts it with the attestor's public key, before posting the response to the attestor.
    /// If post request is successful, the updated ```IdentityCRChallenge``` is returned.
    pub async fn send_identity_response(
        self,
        attestor_p_key: &Jwk,
    ) -> Result<Attestation<IdentityResponseShared>, TrustchainCRError> {
        // Read the temporary secret key from file.
        let temp_s_key = self.read_temp_s_key()?;
        let temp_s_key_ssi = josekit_to_ssi_jwk(&temp_s_key).unwrap();

        // Decrypt and verify the identity challenge.
        let requester = Entity {};
        let decrypted_verified_payload = requester.decrypt_and_verify(
            self.identity_challenge_signature
                .as_ref()
                .expect("Some value guaranteed by state.")
                .to_string(),
            &temp_s_key,
            &attestor_p_key,
        )?;
        // Sign and encrypt the response.
        let identity_response_signature = requester
            .sign_and_encrypt_claim(&decrypted_verified_payload, &temp_s_key, &attestor_p_key)
            .unwrap();
        let key_id = temp_s_key_ssi.to_public().thumbprint().unwrap();

        // Get endpoint and URI. TODO: use URI type.
        // let services = get_services(&self.udid());
        // let endpoint = matching_endpoint(services, ATTESTATION_FRAGMENT).unwrap();
        let endpoint =
            attestation_endpoint(&self.udid.as_ref().expect("Some value guaranteed by state."))?;
        let url_path = "/did/attestor/identity/respond";
        let uri = format!("{}{}/{}", endpoint, url_path, key_id);

        // POST the response to the identity challenge.
        let client = reqwest::Client::new();
        let result = client
            .post(uri)
            .json(&identity_response_signature)
            .send()
            .await
            .map_err(|err| TrustchainCRError::Reqwest(err))?;
        if result.status() != 200 {
            return Err(TrustchainCRError::FailedToRespond(result));
        }

        let updated_attestation = Attestation {
            requester_details: self.requester_details,
            temp_p_key_ssi: self.temp_p_key_ssi,
            temp_p_key: self.temp_p_key,
            udid: self.udid,
            update_p_key: self.update_p_key,
            identity_nonce: self.identity_nonce,
            identity_challenge_signature: self.identity_challenge_signature,
            identity_response_signature: Some(identity_response_signature),
            ddid: None,
            content_nonces: None,
            content_challenge_signature: None,
            content_response_signature: None,
            state: std::marker::PhantomData::<IdentityResponseShared>,
        };

        // TODO: serialise the updated attestation (to update the persistent state on the attestor side).

        Ok(updated_attestation)
    }

    // Attestor side.
    /// Updates state by admitting the identity response (that was received from the requester).
    pub fn admit_identity_response(
        self,
        identity_response_signature: &str,
    ) -> Attestation<IdentityResponseShared> {
        let updated_attestation = Attestation {
            requester_details: self.requester_details,
            temp_p_key_ssi: self.temp_p_key_ssi,
            temp_p_key: self.temp_p_key,
            udid: self.udid,
            update_p_key: self.update_p_key,
            identity_nonce: self.identity_nonce,
            identity_challenge_signature: self.identity_challenge_signature,
            identity_response_signature: Some(identity_response_signature.to_string()),
            ddid: None,
            content_nonces: None,
            content_challenge_signature: None,
            content_response_signature: None,
            state: std::marker::PhantomData::<IdentityResponseShared>,
        };

        // TODO: serialise the updated attestation (to update the persistent state on the requester side).

        updated_attestation
    }
}

/// State of the Attestation after the identity response has been shared by requester and received
/// (and admitted) by the attestor.
impl Attestation<IdentityResponseShared> {
    // Static deserialisation constructor.
    pub fn deserialise(
        path: &PathBuf,
    ) -> Result<Attestation<IdentityResponseShared>, TrustchainCRError> {
        todo!();

        // Read these parameters from file:
        // requester_details: RequesterDetails,
        // temp_p_key_ssi: JWK,
        // temp_p_key: Jwk,
        // udid: String,
        // update_p_key: Jwk,
        // identity_nonce: Nonce,
        // identity_challenge_signature: String,
        // identity_response_signature: String

        // // Return the Attestation in state IdentityResponseShared.
        // Ok(Attestation {
        //     requester_details: self.requester_details,
        //     temp_p_key_ssi: self.temp_p_key_ssi,
        //     temp_p_key: self.temp_p_key,
        //     udid: Some(udid.to_string()),
        //     update_p_key: Some(update_p_key),
        //     identity_nonce: Some(identity_nonce),
        //     identity_challenge_signature: Some(identity_challenge_signature),
        //     identity_response_signature: Some(identity_response_signature),
        //     ddid: None,
        //     content_nonces: None,
        //     content_challenge_signature: None,
        //     content_response_signature: None,
        //     state: std::marker::PhantomData::<IdentityChallengeShared>,
        // })
    }

    // Attestor side.
    /// Verifies the identity nonce for part one of attestation process (identity challenge-response).
    /// nonce from the file and compares it with the nonce from the payload.
    fn verify_identity_nonce(&self) -> Result<(), TrustchainCRError> {
        // Verify the signature on the identity response using the temporary public key.
        todo!();

        // // Extract the nonce from the identity response signature message.
        // let received_nonce = self.identity_response_signature?;

        // // Reconstruct the JwtPayload.
        // let nonce = payload
        //     .claim("identity_nonce")
        //     .ok_or(TrustchainCRError::ClaimNotFound)?
        //     .as_str()
        //     .ok_or(TrustchainCRError::FailedToConvertToStr(
        //         // Unwrap: not None since error would have propagated above if None
        //         payload.claim("identity_nonce").unwrap().clone(),
        //     ))?;

        // let expected_nonce = self
        //     .identity_nonce
        //     .as_ref()
        //     .expect("Some value guaranteed by state.");

        // if received_nonce != expected_nonce {
        //     return Err(TrustchainCRError::FailedToVerifyNonce);
        // }
        // Ok(())
    }

    // Requester side.
    // NOTE: the ContentChallengeShared state is skipped on the requester side (but not on the
    // attestor side) because, having received the content challenge the requester can immediately
    // respond to it, resulting in either completion of the content challenge or an error.
    //
    /// This function posts the candidate DID (dDID) to the attestor's endpoint.
    /// If the post request is successful, the response body contains the signed and encrypted
    /// challenge payload with a hashmap that contains an encrypted nonce per signing key.
    /// The response to the challenge is generated and posted to the attestor's endpoint.
    /// If the post request and the verification of the response are successful, the
    /// ```ContentCRInitiation``` and ```CRContentChallenge``` structs are returned.
    pub async fn content_challenge_response(
        self,
        udid: &str,
        ddid: &str,
    ) -> Result<Attestation<ContentChallengeComplete>, TrustchainCRError> {
        // Get endpoint and URI. TODO: use URI type.
        let url_path = "/did/attestor/content/initiate";
        let endpoint = attestation_endpoint(&udid)?;
        let uri = format!("{}{}", endpoint, url_path);

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
            return Err(TrustchainCRError::FailedToRespond(result));
        }

        let response_body: CustomResponse = result
            .json()
            .await
            .map_err(|err| TrustchainCRError::Reqwest(err))?;
        let signed_encrypted_challenge = response_body.data.unwrap();

        // Read the temporary secret key from file.
        let temp_s_key = self.read_temp_s_key()?;

        // Get the attestor's public key from the uDID.
        let attestor_p_key = self.attestation_public_key(
            &self.udid.as_ref().expect("Some value guaranteed by state."),
        )?;

        // Decrypt and verify the response payload.
        let requester = Entity {};
        let decrypted_verified_payload = requester.decrypt_and_verify(
            signed_encrypted_challenge.to_owned(),
            &temp_s_key,
            &attestor_p_key,
        )?;

        // Extract the (decrypted) nonces that constitute the dDID content challenge.
        let challenges_map: HashMap<String, String> = serde_json::from_value(
            decrypted_verified_payload
                .claim("challenges")
                .unwrap()
                .clone(),
        )?;
        // Note: we shouldn't need to decrypt these nonces individually. They have already been
        // decrypted using the temporary secret key. The signature on each will prove possession
        // of the corresponding secret key.
        let content_nonces: HashMap<String, Nonce> =
            challenges_map
                .iter()
                .fold(HashMap::new(), |mut acc, (key_id, nonce)| {
                    acc.insert(String::from(key_id), Nonce::from(nonce.clone()));
                    acc
                });

        // Instead of updating the Attestation at this point, continue with the response to the
        // content challenge.

        // Note: we sign each of the nonces with the corresponding secret key (for the given key_id)
        // so that these signatures serve as a lasting proof that the challenge was met.
        // (Decrypting them with the secret key would also prove possession, but could not be
        // subsequently verified so there's no lasting proof).

        // TODO:
        // Sign and encrypt each of the content nonces.

        // let value: serde_json::Value = serde_json::to_value(&content_nonces).unwrap();
        // let mut payload = JwtPayload::new();
        // payload.set_claim("nonces", Some(value)).unwrap();
        // let signed_encrypted_response = requester
        //     .sign_and_encrypt_claim(&payload, &temp_s_key, &attestor_p_key)
        //     .unwrap();

        // old version, where nonces are decrypted individually but not signed:

        // let signed_nonces: HashMap<String, Nonce> =
        // challenges_map
        //     .iter()
        //     .fold(HashMap::new(), |mut acc, (key_id, nonce)| {
        //         acc.insert(
        //             String::from(key_id),
        //             Nonce::from(
        //                 requester
        //                     .decrypt(
        //                         &Some(Value::from(nonce.clone())).unwrap(),
        //                         signing_keys_map.get(key_id).unwrap(),
        //                     )
        //                     .unwrap()
        //                     .claim("nonce")
        //                     .unwrap()
        //                     .as_str()
        //                     .unwrap()
        //                     .to_string(),
        //             ),
        //         );

        //         acc
        //     });

        // // POST the response to the content challenge.
        // let client = reqwest::Client::new();
        // let result = client
        //     .post(uri)
        //     .json(&signed_encrypted_response)
        //     .send()
        //     .await
        //     .map_err(|err| TrustchainCRError::Reqwest(err))?;
        // if result.status() != 200 {
        //     println!("Status code: {}", result.status());
        //     return Err(TrustchainCRError::FailedToRespond(result));
        // }

        let updated_attestation = Attestation {
            requester_details: self.requester_details,
            temp_p_key_ssi: self.temp_p_key_ssi,
            temp_p_key: self.temp_p_key,
            udid: self.udid,
            update_p_key: self.update_p_key,
            identity_nonce: self.identity_nonce,
            identity_challenge_signature: self.identity_challenge_signature,
            identity_response_signature: self.identity_response_signature,
            ddid: Some(ddid.to_string()),
            content_nonces: Some(content_nonces), // todo.
            content_challenge_signature: None,    // todo.
            content_response_signature: None,     // todo.
            state: std::marker::PhantomData::<ContentChallengeComplete>,
        };

        // TODO: serialise the updated attestation (to update the persistent state on the requester side).

        Ok(updated_attestation)
    }

    // THIS HAPPENS IN THE POST HTTP HANDLER:
    // // Attestor side.
    // fn send_content_challenge(
    //     self,
    // ) -> Result<Attestation<ContentChallengeShared>, TrustchainCRError> {
    //     // Verify the identity nonce. If this check fails, stop the process.
    //     if self.verify_identity_nonce().is_err() {
    //         return Err(TrustchainCRError::FailedToVerifyNonce);
    //     }
    // }
}

impl<State> Attestation<State> {
    // pub fn temp_p_key_ssi(&self) -> &JWK {
    //     &self.temp_p_key_ssi
    // }

    // pub fn temp_p_key(&self) -> &Jwk {
    //     &self.temp_p_key
    // }

    // Requester side.
    /// Reads the temporary secret key. Returns an error if called by the attestor.
    fn read_temp_s_key(&self) -> Result<Jwk, TrustchainCRError> {
        todo!()
    }

    // Requester side.
    /// Gets the attestor's public key for attestation operations from the uDID.
    fn attestation_public_key(&self, udid: &str) -> Result<Jwk, TrustchainCRError> {
        todo!()
    }

    // Both sides.
    /// Returns the directory path in which data is stored relating to this attestation request.
    pub fn attestation_request_path(&self, prefix: &str) -> Result<PathBuf, TrustchainCRError> {
        attestation_request_path(&self.temp_p_key_ssi, prefix)
        // TODO: consider replacing `prefix` with a boolean is_request.
    }
}

impl<State> Attestation<State> {
    // Getter for requester_details.
    pub fn requester_details(&self) -> RequesterDetails {
        self.requester_details.clone()
    }
}

#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, Clone)]
/// Type for storing initiation details of the attestation request.
pub struct AttestationRequest {
    pub temp_p_key: Jwk,
    pub requester_details: RequesterDetails,
}
