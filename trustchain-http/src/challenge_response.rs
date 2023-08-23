use josekit::jwe::{JweHeader, ECDH_ES};
use josekit::jwk::Jwk;
use josekit::jws::{JwsHeader, ES256K};
use josekit::jwt::{self, JwtPayload};
use josekit::JoseError;
use rand::thread_rng;
use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use ssi::did::{Document, VerificationMethod};
use ssi::jwk::JWK;
use std::collections::HashMap;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TrustchainCRError {
    /// Serde JSON error.
    #[error("Wrapped serialization error: {0}")]
    Serde(serde_json::Error),
    /// Wrapped jose error.
    #[error("Wrapped jose error: {0}")]
    Jose(JoseError),
    /// Missing JWK from verification method.
    #[error("Missing JWK from verification method of a DID document.")]
    MissingJWK,
    /// Key not found in hashmap.
    #[error("Key id not found.")]
    KeyNotFound,
    /// Claim not found in JWTPayload.
    #[error("Claim not found in JWTPayload.")]
    ClaimNotFound,
    /// Nonce type invalid.
    #[error("Invalid nonce type.")]
    InvalidNonceType,
}

impl From<JoseError> for TrustchainCRError {
    fn from(err: JoseError) -> Self {
        Self::Jose(err)
    }
}

// pub struct Nonce<const N: usize>([u8; N]);
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct Nonce(String);

// impl<const N: usize> Nonce<N> {
impl Nonce {
    pub fn new() -> Self {
        Self(
            thread_rng()
                .sample_iter(&Alphanumeric)
                .take(32)
                .map(char::from)
                .collect(),
        )
    }
}

impl AsRef<str> for Nonce {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl ToString for Nonce {
    fn to_string(&self) -> String {
        self.0.clone()
    }
}

impl From<String> for Nonce {
    fn from(s: String) -> Self {
        Self(s)
    }
}

#[derive(Debug)]
struct CRState {
    initiation: Option<CRInitiation>,
    identity_challenge_response: Option<CRIdentityChallenge>,
}

struct Entity {}

trait ElementwiseSerializeDeserialize {
    fn elementwise_serialize(&self) -> Result<(), TrustchainCRError>;
    // todo: default implementation, look if exists already
    fn elementwise_deserialize(&self) -> Result<(), TrustchainCRError>;
}

#[derive(Debug, Serialize, Deserialize)]
struct RequesterDetails {
    requester_org: String,
    operator_name: String,
}

#[derive(Debug)]
struct CRInitiation {
    temp_p_key: Jwk,
    requester_details: RequesterDetails,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct CRIdentityChallenge {
    update_p_key: Option<Jwk>,
    identity_nonce: Option<Nonce>, // make own Nonce type
    identity_challenge_signature: Option<String>,
    identity_response_signature: Option<String>,
}

struct CRContentChallenge {
    content_nonce: Option<HashMap<String, Nonce>>,
    content_challenge_signature: Option<String>,
    content_response_signature: Option<String>,
}

impl TryFrom<&CRIdentityChallenge> for JwtPayload {
    type Error = TrustchainCRError;
    fn try_from(value: &CRIdentityChallenge) -> Result<Self, Self::Error> {
        let mut payload = JwtPayload::new();
        payload.set_claim(
            "identity_nonce",
            Some(Value::from(
                value.identity_nonce.as_ref().unwrap().to_string(),
            )),
        )?;
        payload.set_claim(
            "update_p_key",
            Some(Value::from(
                value.update_p_key.as_ref().unwrap().to_string(),
            )),
        )?;
        Ok(payload)
    }
}

impl TryFrom<&JwtPayload> for CRIdentityChallenge {
    type Error = TrustchainCRError;
    fn try_from(value: &JwtPayload) -> Result<Self, Self::Error> {
        let mut challenge = CRIdentityChallenge {
            update_p_key: None,
            identity_nonce: None,
            identity_challenge_signature: None,
            identity_response_signature: None,
        };
        challenge.update_p_key = Some(
            serde_json::from_str(value.claim("update_p_key").unwrap().as_str().unwrap()).unwrap(),
        );
        challenge.identity_nonce = Some(Nonce::from(
            value
                .claim("identity_nonce")
                .unwrap()
                .as_str()
                .unwrap()
                .to_string(),
        ));
        Ok(challenge)
    }
}

impl TryFrom<&Nonce> for JwtPayload {
    type Error = TrustchainCRError;
    fn try_from(value: &Nonce) -> Result<Self, Self::Error> {
        let mut payload = JwtPayload::new();
        payload.set_claim("nonce", Some(Value::from(value.to_string())))?;
        Ok(payload)
    }
}

// impl TryFrom<(&JwtPayload, Vec<&str>)> for CRIdentityChallenge {
//     type Error = TrustchainCRError;
//     fn try_from((value, claims): (&JwtPayload, Vec<&str>)) -> Result<Self, Self::Error> {
//         let mut challenge = CRIdentityChallenge {
//             update_p_key: None,
//             identity_nonce: None,
//             identity_challenge_signature: None,
//             identity_response_signature: None,
//         };

//         for claim in claims {
//             match claim {
//                 "update_p_key" => {
//                     challenge.update_p_key = Some(
//                         serde_json::from_str(
//                             value.claim("update_p_key").unwrap().as_str().unwrap(),
//                         )
//                         .unwrap(),
//                     );
//                 }
//                 "identity_nonce" => {
//                     challenge.identity_nonce = Some(
//                         value
//                             .claim("identity_nonce")
//                             .unwrap()
//                             .as_str()
//                             .unwrap()
//                             .to_string(),
//                     );
//                 }
//                 _ => {}
//             }
//         }

//         Ok(challenge)
//     }
// }

/// Interface for signing and then encrypting data.
pub trait SignEncrypt {
    fn sign(&self, payload: &JwtPayload, secret_key: &Jwk) -> Result<String, TrustchainCRError> {
        let mut header = JwsHeader::new();
        header.set_token_type("JWT");
        let signer = ES256K.signer_from_jwk(&secret_key)?;
        let signed_jwt = jwt::encode_with_signer(payload, &header, &signer)?;
        Ok(signed_jwt)
    }
    /// `JWTPayload` is a wrapped [`Map`](https://docs.rs/serde_json/1.0.79/serde_json/struct.Map.html)
    /// of claims.
    fn encrypt(&self, payload: &JwtPayload, public_key: &Jwk) -> Result<String, TrustchainCRError> {
        let mut header = JweHeader::new();
        header.set_token_type("JWT");
        header.set_content_encryption("A128CBC-HS256");
        header.set_content_encryption("A256GCM");

        let encrypter = ECDH_ES.encrypter_from_jwk(&public_key)?;
        let encrypted_jwt = jwt::encode_with_encrypter(payload, &header, &encrypter)?;
        Ok(encrypted_jwt)
    }
    /// Combined sign and encryption
    fn sign_and_encrypt_claim(
        &self,
        payload: &JwtPayload,
        secret_key: &Jwk,
        public_key: &Jwk,
    ) -> Result<String, TrustchainCRError> {
        let signed_encoded_payload = self.sign(payload, secret_key)?;
        let mut claims = JwtPayload::new();
        claims.set_claim("claim", Some(Value::from(signed_encoded_payload)))?;
        self.encrypt(&claims, &public_key)
    }
}
/// Interface for decrypting and then verifying data.
trait DecryptVerify {
    fn decrypt(&self, value: &Value, secret_key: &Jwk) -> Result<JwtPayload, TrustchainCRError> {
        let decrypter = ECDH_ES.decrypter_from_jwk(&secret_key)?;
        let (payload, _) = jwt::decode_with_decrypter(value.as_str().unwrap(), &decrypter)?;
        Ok(payload)
    }
    fn decrypt_and_verify(
        &self,
        input: String,
        secret_key: &Jwk,
        public_key: &Jwk,
    ) -> Result<JwtPayload, TrustchainCRError> {
        let decrypter = ECDH_ES.decrypter_from_jwk(secret_key)?;
        let (payload, _) = jwt::decode_with_decrypter(input, &decrypter)?;

        let verifier = ES256K.verifier_from_jwk(public_key)?;
        let (payload, _) = jwt::decode_with_verifier(
            &payload.claim("claim").unwrap().as_str().unwrap(),
            &verifier,
        )?;
        Ok(payload)
    }
}

impl SignEncrypt for Entity {}

impl DecryptVerify for Entity {}

///  Generates a random alphanumeric nonce of a specified length using a seeded random number generator.
fn generate_nonce() -> String {
    // let rng: StdRng = SeedableRng::seed_from_u64(seed);
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}

// make a try_from instead
fn josekit_to_ssi_jwk(key: &Jwk) -> Result<JWK, serde_json::Error> {
    let key_as_str: &str = &serde_json::to_string(&key).unwrap();
    let ssi_key: JWK = serde_json::from_str(key_as_str).unwrap();
    Ok(ssi_key)
}

fn ssi_to_josekit_jwk(key: &JWK) -> Result<Jwk, serde_json::Error> {
    let key_as_str: &str = &serde_json::to_string(&key).unwrap();
    let ssi_key: Jwk = serde_json::from_str(key_as_str).unwrap();
    Ok(ssi_key)
}

fn extract_key_ids_and_jwk(document: &Document) -> Result<HashMap<String, Jwk>, TrustchainCRError> {
    let mut my_map = HashMap::<String, Jwk>::new();
    if let Some(vms) = &document.verification_method {
        // TODO: leave the commented code
        // vms.iter().for_each(|vm| match vm {
        //     VerificationMethod::Map(vm_map) => {
        //         let id = vm_map.id;
        //         let key = vm_map.get_jwk().unwrap();
        //         let key_jose = ssi_to_josekit_jwk(&key).unwrap();
        //         my_map.insert(id, key_jose);
        //     }
        //     _ => (),
        // });
        // TODO: consider rewriting functional with filter, partition, fold over returned error
        // variants.
        for vm in vms {
            match vm {
                VerificationMethod::Map(vm_map) => {
                    // let id = vm_map.id.clone(); // TODo: use JWK::thumbprint() instead
                    let key = vm_map
                        .get_jwk()
                        .map_err(|_| TrustchainCRError::MissingJWK)?;
                    let id = key
                        .thumbprint()
                        .map_err(|_| TrustchainCRError::MissingJWK)?; //TODO: different error variant?
                    let key_jose =
                        ssi_to_josekit_jwk(&key).map_err(|err| TrustchainCRError::Serde(err))?;
                    my_map.insert(id, key_jose);
                }
                _ => (),
            }
        }
    }
    Ok(my_map)
}

#[cfg(test)]
mod tests {

    use crate::data::{
        TEST_SIDETREE_DOCUMENT_MULTIPLE_KEYS, TEST_SIGNING_KEY_1, TEST_SIGNING_KEY_2,
        TEST_TEMP_KEY, TEST_UPDATE_KEY, TEST_UPSTREAM_KEY,
    };

    use super::*;

    #[test]
    fn test_identity_challenge_response() {
        // ==========| UE - generate challenge | ==============
        let upstream_s_key: Jwk = serde_json::from_str(TEST_UPSTREAM_KEY).unwrap();
        let update_key: Jwk = serde_json::from_str(TEST_UPDATE_KEY).unwrap();
        let temp_s_key: Jwk = serde_json::from_str(TEST_TEMP_KEY).unwrap();
        let temp_p_key = temp_s_key.to_public_key().unwrap();

        // generate challenge
        let request_initiation = CRInitiation {
            temp_p_key: temp_p_key.clone(),
            requester_details: RequesterDetails {
                requester_org: String::from("My Org"),
                operator_name: String::from("John Doe"),
            },
        };

        let mut upstream_identity_challenge_response = CRIdentityChallenge {
            update_p_key: Some(update_key.clone()),
            identity_nonce: Some(Nonce::new()),
            identity_challenge_signature: None,
            identity_response_signature: None,
        };

        // sign and encrypt
        let upstream_entity = Entity {};

        let payload = JwtPayload::try_from(&upstream_identity_challenge_response).unwrap();
        let signed_encrypted_challenge = upstream_entity
            .sign_and_encrypt_claim(&payload, &upstream_s_key, &request_initiation.temp_p_key)
            .unwrap();

        upstream_identity_challenge_response.identity_challenge_signature =
            Some(signed_encrypted_challenge);

        // ==========| DE - generate response | ==============

        // decrypt and verify
        let downstream_entity = Entity {};
        let upstream_p_key = upstream_s_key.to_public_key().unwrap();
        let signed_encrypted_challenge = upstream_identity_challenge_response
            .identity_challenge_signature
            .clone()
            .unwrap();

        let decrypted_verified_challenge = downstream_entity
            .decrypt_and_verify(signed_encrypted_challenge, &temp_s_key, &upstream_p_key)
            .unwrap();
        let downstream_identity_challenge =
            CRIdentityChallenge::try_from(&decrypted_verified_challenge).unwrap();

        // generate response
        let mut payload = JwtPayload::new();
        payload
            .set_claim(
                "identity_nonce",
                Some(Value::from(
                    downstream_identity_challenge
                        .identity_nonce
                        .as_ref()
                        .unwrap()
                        .to_string(),
                )),
            )
            .unwrap();
        let signed_encrypted_response = downstream_entity
            .sign_and_encrypt_claim(&payload, &temp_s_key, &upstream_p_key)
            .unwrap();

        // ==========| UE - verify response | ==============

        // decrypt and verify signature
        let decrypted_verified_response = upstream_entity
            .decrypt_and_verify(signed_encrypted_response, &upstream_s_key, &temp_p_key)
            .unwrap();

        let nonce = decrypted_verified_response
            .claim("identity_nonce")
            .unwrap()
            .as_str()
            .unwrap();

        let expected_nonce = upstream_identity_challenge_response
            .identity_nonce
            .unwrap()
            .to_string();
        assert_eq!(nonce, expected_nonce);
    }

    #[test]
    fn test_content_challenge_response() {
        // ==========| UE - generate challenge | ==============
        let upstream_entity = Entity {};
        let upstream_s_key: Jwk = serde_json::from_str(TEST_UPSTREAM_KEY).unwrap();
        let temp_s_key: Jwk = serde_json::from_str(TEST_TEMP_KEY).unwrap();
        let temp_p_key = temp_s_key.to_public_key().unwrap();
        // get signing keys for DE from did document
        let doc: Document = serde_json::from_str(TEST_SIDETREE_DOCUMENT_MULTIPLE_KEYS).unwrap();
        let test_keys_map = extract_key_ids_and_jwk(&doc).unwrap();

        // generate map with unencrypted nonces so UE can store them for later verification
        let nonces: HashMap<String, Nonce> =
            test_keys_map
                .iter()
                .fold(HashMap::new(), |mut acc, (key_id, _)| {
                    acc.insert(String::from(key_id), Nonce::new());
                    acc
                });

        for (_, val) in &nonces {
            println!("{:?}", val);
        }

        // turn nonces into challenges by encrypting them with the public keys of UE
        let challenges = nonces
            .iter()
            .fold(HashMap::new(), |mut acc, (key_id, nonce)| {
                acc.insert(
                    String::from(key_id),
                    upstream_entity
                        .encrypt(
                            &JwtPayload::try_from(nonce).unwrap(),
                            &test_keys_map.get(key_id).unwrap(),
                        )
                        .unwrap(),
                );
                acc
            });

        // sign (UE private key) and encrypt (DE temp public key) entire challenge
        let value: serde_json::Value = serde_json::to_value(challenges).unwrap();
        let mut payload = JwtPayload::new();
        payload.set_claim("challenges", Some(value)).unwrap();
        let signed_encrypted_challenges = upstream_entity
            .sign_and_encrypt_claim(&payload, &upstream_s_key, &temp_p_key)
            .unwrap();

        // ==========| DE - generate response | ==============
        let downstream_entity = Entity {};
        let upstream_p_key = upstream_s_key.to_public_key().unwrap();

        // decrypt and verify signature on challenges
        let decrypted_verified_challenges = downstream_entity
            .decrypt_and_verify(signed_encrypted_challenges, &temp_s_key, &upstream_p_key)
            .unwrap();

        // decrypt nonces from challenges
        let challenges_map: HashMap<String, String> = serde_json::from_value(
            decrypted_verified_challenges
                .claim("challenges")
                .unwrap()
                .clone(),
        )
        .unwrap();

        // todo: replace with function to read in private keys
        let downstream_s_key_1: Jwk = serde_json::from_str(TEST_SIGNING_KEY_1).unwrap();
        let downstream_s_key_2: Jwk = serde_json::from_str(TEST_SIGNING_KEY_2).unwrap();
        let downstream_key_id_1 = josekit_to_ssi_jwk(&downstream_s_key_1)
            .unwrap()
            .thumbprint()
            .unwrap();
        let downstream_key_id_2 = josekit_to_ssi_jwk(&downstream_s_key_2)
            .unwrap()
            .thumbprint()
            .unwrap();

        let mut downstream_s_keys_map: HashMap<String, Jwk> = HashMap::new();
        downstream_s_keys_map.insert(downstream_key_id_1, downstream_s_key_1);
        downstream_s_keys_map.insert(downstream_key_id_2, downstream_s_key_2);

        let decrypted_nonces: HashMap<String, String> =
            challenges_map
                .iter()
                .fold(HashMap::new(), |mut acc, (key_id, nonce)| {
                    acc.insert(
                        String::from(key_id),
                        downstream_entity
                            .decrypt(
                                &Some(Value::from(nonce.clone())).unwrap(),
                                downstream_s_keys_map.get(key_id).unwrap(),
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
        let signed_encrypted_response = downstream_entity
            .sign_and_encrypt_claim(&payload, &temp_s_key, &upstream_p_key)
            .unwrap();

        // ==========| UE - verify response | ==============
        let decrypted_verified_response = upstream_entity
            .decrypt_and_verify(signed_encrypted_response, &upstream_s_key, &temp_p_key)
            .unwrap();
        println!(
            "Decrypted and verified response: {:?}",
            decrypted_verified_response
        );
        let verified_response_map: HashMap<String, Nonce> =
            serde_json::from_value(decrypted_verified_response.claim("nonces").unwrap().clone())
                .unwrap();
        println!("Verified response map: {:?}", verified_response_map);
        assert_eq!(verified_response_map, nonces);
    }
}
