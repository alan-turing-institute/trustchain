use std::{collections::HashMap, str::FromStr};

use josekit::{
    jwe::JweHeader,
    jwe::ECDH_ES,
    jwk::Jwk,
    jws::{JwsHeader, ES256K},
    jwt::{self, JwtPayload},
    JoseError,
};
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use serde::{Deserialize, Serialize};
use serde_json::{from_value, Value};
use sha2::{Digest, Sha256};
use ssi::did::Document;
use ssi::did::VerificationMethod;
use ssi::jwk::JWK;
use thiserror::Error;

const TEMP_PRIVATE_KEY: &str = r#"{"kty":"EC","crv":"secp256k1","x":"JokHTNHd1lIw2EXUTV1RJL3wvWMgoIRHPaWxTHcyH9U","y":"z737jJY7kxW_lpE1eZur-9n9_HUEGFyBGsTdChzI4Kg","d":"CfdUwQ-CcBQkWpIDPjhSJAq2SCg6hAGdcvLmCj0aA-c"}"#;
const TEMP_PUB_KEY: &str = r#"{"kty":"EC","crv":"secp256k1","x":"JokHTNHd1lIw2EXUTV1RJL3wvWMgoIRHPaWxTHcyH9U","y":"z737jJY7kxW_lpE1eZur-9n9_HUEGFyBGsTdChzI4Kg"}"#;
const UPSTREAM_PRIVATE_KEY: &str = r#"{"kty":"EC","crv":"secp256k1","x":"JEV4WMgoJekTa5RQD5M92P1oLjdpMNYETQ3nbtKSnLQ","y":"dRfg_5i5wcMg1lxAffQORHpzgtm2yEIqgJoUk5ZklvI","d":"DZDZd9bxopCv2YJelMpQm_BJ0awvzpT6xWdWbaQlIJI"}"#;
const UPSTREAM_PUB_KEY: &str = r#"{"kty":"EC","crv":"secp256k1","x":"JEV4WMgoJekTa5RQD5M92P1oLjdpMNYETQ3nbtKSnLQ","y":"dRfg_5i5wcMg1lxAffQORHpzgtm2yEIqgJoUk5ZklvI"}"#;
const DOWNSTREAM_PRIV_KEY_1: &str = r#"{"kty":"EC","crv":"secp256k1","x":"Lt2ys7LE0ELccVtCETtVjMFavgjwYDjDBtuV_XCH7-g","y":"TdTT8oXUSXMvFbhnsYrqwOkL7-niHWFxW0vaBSnUMnI","d":"B7csdham680yGiIdxeyllmczap7-h6_LtKunRhRqfic"}"#;
const DOWNSTREAM_PUB_KEY_1: &str = r#"{"kty":"EC","crv":"secp256k1","x":"Lt2ys7LE0ELccVtCETtVjMFavgjwYDjDBtuV_XCH7-g","y":"TdTT8oXUSXMvFbhnsYrqwOkL7-niHWFxW0vaBSnUMnI"}"#;
const DOWNSTREAM_PRIV_KEY_2: &str = r#"{"kty":"EC","crv":"secp256k1","x":"AB1b_4-XSem0uiPGGuW_hf_AuPArukMuD2S95ypGDSE","y":"suvBnCbhicPdYZeqgxJfPFmiNHGYDjPiW8XkYHxwgBU","d":"V3zmieRjP9LYa1v8l8lYXh4LqU87bPspSAGqq34Up1Q"}"#;
const DOWNSTREAM_PUB_KEY_2: &str = r#"{"kty":"EC","crv":"secp256k1","x":"AB1b_4-XSem0uiPGGuW_hf_AuPArukMuD2S95ypGDSE","y":"suvBnCbhicPdYZeqgxJfPFmiNHGYDjPiW8XkYHxwgBU"}"#;

#[derive(Error, Debug)]
pub enum TrustchainCRError {
    /// Serde JSON error.
    #[error("Wrapped serialization error: {0}")]
    Serde(serde_json::Error),
    /// Wrapped jose error.
    #[error("Wrapped jose error: {0}")]
    Jose(JoseError),
    /// Missing JWK from verification method
    #[error("Missing JWK from verification method of a DID document.")]
    MissingJWK,
    /// Key not found in hashmap
    #[error("Key id not found.")]
    KeyNotFound,
}

pub struct IdentityChallenge {
    nonce: String,             // Maybe create a new Nonce type
    update_commitment: String, // TODO: this should be a key, format???
}
#[derive(Debug, Serialize, Deserialize)]
pub struct ContentChallengeItem {
    encrypted_nonce: String,
    hash_public_key: String,
}

pub struct KeysCR {
    private_key: Jwk,
    public_key: Jwk,
}

pub struct KeyPairs {
    private_key: Jwk,
    public_key: Jwk,
}

// Orphan rule: need new trait in crate or new type.
// New trait:
trait ToJwk {
    fn to_jwk(&self) -> Jwk {
        todo!()
    }
}

// New type:
// Or we make our own key type (wrapper)
// Named field version
pub struct MyJWKNamedField {
    key: Jwk,
}
// Tuple struct version
pub struct MyJWK(Jwk);

impl From<MyJWK> for Jwk {
    fn from(value: MyJWK) -> Self {
        value.0
    }
}

impl From<MyJWK> for JWK {
    fn from(value: MyJWK) -> Self {
        josekit_to_ssi_jwk(&value.0).unwrap() // copy code of function in here
    }
}

impl From<JWK> for MyJWK {
    fn from(value: JWK) -> Self {
        todo!()
    }
}

impl From<Jwk> for MyJWK {
    fn from(value: Jwk) -> Self {
        todo!()
    }
}

// Ideas for structs:
/// A type for upstream entity?
struct UE {
    keys_cr: KeysCR,
}

/// A type for downstream entity?
struct DE;

pub trait CRStateIO {
    // read() returns any struct that implements the CRState trait (eg. Step2Claim)
    // (the Box<> is needed because the different structs that could be returned will likely have
    // different sizes)
    fn read(&self) -> Box<dyn CRState>;
    fn write(&self, payload: &str);
}

// An empty trait implimented by all data types, eg. Step2Claim?
trait CRState {
    fn status(&self) {
        println!("Ok");
    }
}

/// A type for a nonce
struct Nonce(String);

// Data type to be read/written to file?
struct Step2Claim {
    nonce: Nonce,
    temp_pub_key: Jwk,
}
impl CRState for Step2Claim {}

// Give the ability to DE to read and write CRState data files
impl CRStateIO for DE {
    fn read(&self) -> Box<dyn CRState> {
        todo!()
    }
    fn write(&self, payload: &str) {
        todo!()
    }
}

// TODO: own type for nonce

trait ChallengeResponse {
    fn sign_and_encrypt(&self, payload: &JwtPayload) -> Result<String, JoseError>;
    fn decrypt_and_verify(&self, input: String) -> Result<JwtPayload, JoseError>;
}

impl ChallengeResponse for KeysCR {
    fn sign_and_encrypt(&self, payload: &JwtPayload) -> Result<String, JoseError> {
        // Sign payload...
        let mut header = JwsHeader::new();
        header.set_token_type("JWT");
        let signer = ES256K.signer_from_jwk(&self.private_key)?;
        let signed_jwt = jwt::encode_with_signer(payload, &header, &signer)?;

        // ... then encrypt
        let mut header = JweHeader::new();
        header.set_token_type("JWT");
        header.set_content_encryption("A128CBC-HS256");
        header.set_content_encryption("A256GCM");

        let mut payload = JwtPayload::new(); // TODO: new name instead of reuse?
        payload.set_claim("signed_jwt", Some(Value::from(signed_jwt.clone())))?;

        let encrypter = ECDH_ES.encrypter_from_jwk(&self.public_key)?;
        let encrypted_jwt = jwt::encode_with_encrypter(&payload, &header, &encrypter)?;
        Ok(encrypted_jwt)
    }
    fn decrypt_and_verify(&self, input: String) -> Result<JwtPayload, JoseError> {
        // Decrypt ...
        let decrypter = ECDH_ES.decrypter_from_jwk(&self.private_key)?;
        let (payload, header) = jwt::decode_with_decrypter(input, &decrypter)?;

        // ... then verify signature on decrypted content
        let verifier = ES256K.verifier_from_jwk(&self.public_key)?;
        let (payload, header) = jwt::decode_with_verifier(
            &payload.claim("signed_jwt").unwrap().as_str().unwrap(),
            &verifier,
        )?;
        Ok(payload)
    }
}

fn generate_nonce() -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}

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

fn present_identity_challenge(
    challenge: &IdentityChallenge,
    keys: &KeysCR,
) -> Result<String, JoseError> {
    let mut payload = JwtPayload::new();
    payload.set_claim("nonce", Some(Value::from(challenge.nonce.clone())))?; // is this a good idea?
    payload.set_claim(
        "update_commitment",
        Some(Value::from(challenge.update_commitment.clone())),
    )?;

    let encrypted_challenge = keys.sign_and_encrypt(&payload).unwrap();
    println!("Please copy + paste this challenge and send it to the responsible operator via alternative channels.");
    println!("Challenge:");
    println!("{}", encrypted_challenge);
    Ok(encrypted_challenge)
}

fn generate_challenge(key: &Jwk) -> Result<String, JoseError> {
    let nonce = generate_nonce();
    println!("Nonce: {}", nonce);

    let encrypted_challenge = encrypt(nonce, &key).unwrap();

    Ok(encrypted_challenge)
}

/// Extracts challenge nonce
fn present_response(challenge: String, keys: &KeysCR) -> Result<String, JoseError> {
    let decrypted_challenge = keys.decrypt_and_verify(challenge).unwrap();

    let nonce = decrypted_challenge
        .claim("nonce")
        .unwrap()
        .as_str()
        .unwrap();
    let mut payload = JwtPayload::new();
    payload.set_claim("nonce", Some(Value::from(nonce)))?;
    let response = keys.sign_and_encrypt(&payload).unwrap();

    Ok(response)
}

/// Verifies if nonce is valid
fn verify_response(response: String, keys: &KeysCR) -> Result<JwtPayload, JoseError> {
    // TODO: only returns payload, we don't verify if nonce correct at this point
    let payload = keys.decrypt_and_verify(response).unwrap();

    Ok(payload)
}

fn present_content_challenge(
    keys: &KeysCR,
    downstream_pub_keys: Vec<&Jwk>,
) -> Result<String, JoseError> {
    // get number of keys

    // generate one nonce per key and encrypt it with key
    // let challenges: HashMap<String, String> =
    //         test_keys_map
    //             .iter()
    //             .fold(HashMap::new(), |mut acc, (key_id, key)| {
    //                 acc.insert(String::from(key_id), generate_challenge(&key).unwrap());
    //                 acc
    //             });
    todo!()
}

fn sign(payload: &JwtPayload, key: &Jwk) -> Result<String, JoseError> {
    let mut header = JwsHeader::new();
    header.set_token_type("JWT");
    let signer = ES256K.signer_from_jwk(key)?;
    let signed_jwt = jwt::encode_with_signer(payload, &header, &signer)?;
    Ok(signed_jwt)
}

fn encrypt(value: String, key: &Jwk) -> Result<String, JoseError> {
    let mut header = JweHeader::new();
    header.set_token_type("JWT");
    header.set_content_encryption("A128CBC-HS256");
    header.set_content_encryption("A256GCM");

    let mut payload = JwtPayload::new();
    payload.set_claim("nonce", Some(Value::from(value.clone())))?;

    let encrypter = ECDH_ES.encrypter_from_jwk(&key)?;
    let encrypted_jwt = jwt::encode_with_encrypter(&payload, &header, &encrypter)?;
    Ok(encrypted_jwt)
}

fn decrypt(input: &Value, key: &Jwk) -> Result<JwtPayload, JoseError> {
    let decrypter = ECDH_ES.decrypter_from_jwk(&key)?;
    let (payload, header) = jwt::decode_with_decrypter(input.as_str().unwrap(), &decrypter)?;
    Ok(payload)
}

/// Extract public keys from did document together with corresponding key ids
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
                    let id = vm_map.id.clone(); // TODo: use JWK::thumbprint() instead
                    let key = vm_map
                        .get_jwk()
                        .map_err(|_| TrustchainCRError::MissingJWK)?;
                    // let id = key
                    //     .thumbprint()
                    //     .map_err(|_| TrustchainCRError::MissingJWK)?; //TODO: different error variant?
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

fn generate_content_response(
    challenges: HashMap<String, String>,
    did_keys_priv: HashMap<String, Jwk>,
    cr_keys: &KeysCR,
) -> Result<String, TrustchainCRError> {
    let decrypted_nonces: HashMap<String, String> =
        challenges
            .iter()
            .fold(HashMap::new(), |mut acc, (key_id, nonce)| {
                acc.insert(
                    String::from(key_id),
                    decrypt(
                        &Some(Value::from(nonce.clone())).unwrap(),
                        did_keys_priv.get(key_id).unwrap(),
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
    // Ok(decrypted_nonces)
    // make payload
    let value: serde_json::Value = serde_json::to_value(decrypted_nonces).unwrap();
    let mut payload = JwtPayload::new();
    payload.set_claim("nonces", Some(value)).unwrap();
    // sign (temp private key) and encrypt (UE public key)
    let encrypted_response = cr_keys.sign_and_encrypt(&payload).unwrap();

    Ok(encrypted_response)
}

fn verify_content_response(
    response: String,
    cr_keys: &KeysCR,
) -> Result<HashMap<String, String>, TrustchainCRError> {
    // verify signature and decrypt response
    let decrypted_response = cr_keys.decrypt_and_verify(response).unwrap();

    // extract response hashmap
    let response_hashmap: HashMap<String, String> =
        serde_json::from_value(decrypted_response.claim("nonces").unwrap().clone()).unwrap();

    Ok(response_hashmap)
}

#[cfg(test)]
mod tests {

    use serde_json::from_str;

    use super::*;
    use crate::data::TEST_SIDETREE_DOCUMENT_MULTIPLE_KEYS;

    #[test]
    fn test_extract_key_ids_and_jwk() {
        let doc: Document = serde_json::from_str(TEST_SIDETREE_DOCUMENT_MULTIPLE_KEYS).unwrap();
        let test_keys_map = extract_key_ids_and_jwk(&doc).unwrap();
        println!("Hash map of DE public keys: {:?}", test_keys_map);

        let expected_key = "#V8jt_0c-aFlq40Uti2R_WiquxuzxyB8kn1cfWmXIU84";
        let first_key = test_keys_map.keys().next().expect("HashMap empty!");
        assert_eq!(
            first_key, expected_key,
            "The first key of the HashMap is not the expected key id."
        );
    }

    #[test]
    fn test_josekit_to_ssi_jwk() {
        let expected_ssi_pub_key: JWK = serde_json::from_str(TEMP_PUB_KEY).unwrap();
        let expected_josekit_pub_key: Jwk = serde_json::from_str(TEMP_PUB_KEY).unwrap();

        let ssi_pub_jwk = josekit_to_ssi_jwk(&expected_josekit_pub_key).unwrap();
        assert!(ssi_pub_jwk.equals_public(&expected_ssi_pub_key));

        let expected_ssi_priv_key: JWK = serde_json::from_str(TEMP_PRIVATE_KEY).unwrap();
        let expected_josekit_priv_key: Jwk = serde_json::from_str(TEMP_PRIVATE_KEY).unwrap();

        let ssi_priv_jwk = josekit_to_ssi_jwk(&expected_josekit_priv_key).unwrap();
        assert_eq!(ssi_priv_jwk, expected_ssi_priv_key);

        let wrong_expected_ssi_priv_key: JWK = serde_json::from_str(UPSTREAM_PRIVATE_KEY).unwrap();
        assert_ne!(ssi_priv_jwk, wrong_expected_ssi_priv_key);
    }

    #[test]
    fn test_ssi_to_josekit_jwk() {
        let expected_ssi_pub_key: JWK = serde_json::from_str(TEMP_PUB_KEY).unwrap();
        let expected_josekit_pub_key: Jwk = serde_json::from_str(TEMP_PUB_KEY).unwrap();

        let josekit_pub_jwk = ssi_to_josekit_jwk(&expected_ssi_pub_key).unwrap();
        assert_eq!(josekit_pub_jwk, expected_josekit_pub_key);

        let expected_ssi_priv_key: JWK = serde_json::from_str(TEMP_PRIVATE_KEY).unwrap();
        let expected_josekit_priv_key: Jwk = serde_json::from_str(TEMP_PRIVATE_KEY).unwrap();

        let josekit_priv_jwk = ssi_to_josekit_jwk(&expected_ssi_priv_key).unwrap();
        assert_eq!(josekit_priv_jwk, expected_josekit_priv_key);
    }

    #[test]
    fn test_identity_challenge_response() {
        // get challenge components and keys ready
        let upstream_cr_keys = KeysCR {
            private_key: serde_json::from_str(UPSTREAM_PRIVATE_KEY).unwrap(),
            public_key: serde_json::from_str(TEMP_PUB_KEY).unwrap(),
        };

        let test_challenge = IdentityChallenge {
            nonce: generate_nonce(),
            update_commitment: String::from("somerandomstringfornow"),
        };
        println!("======================");
        println!("The nonce is: {}", test_challenge.nonce);
        println!("======================");
        let presented_challenge =
            present_identity_challenge(&test_challenge, &upstream_cr_keys).unwrap();

        // get keys for response ready
        let downstream_cr_keys = KeysCR {
            private_key: serde_json::from_str(TEMP_PRIVATE_KEY).unwrap(),
            public_key: serde_json::from_str(UPSTREAM_PUB_KEY).unwrap(),
        };
        let response = present_response(presented_challenge, &downstream_cr_keys).unwrap();

        let verified_response = verify_response(response, &upstream_cr_keys).unwrap();
        let nonce_from_response = verified_response.claim("nonce").unwrap().as_str().unwrap();
        println!("======================");
        println!("Verified response: {}", nonce_from_response);
        println!("======================");
        assert_eq!(test_challenge.nonce, nonce_from_response);
    }

    #[test]
    fn test_content_response() {
        // keys the UE needs
        let upstream_cr_keys = KeysCR {
            private_key: serde_json::from_str(UPSTREAM_PRIVATE_KEY).unwrap(),
            public_key: serde_json::from_str(TEMP_PUB_KEY).unwrap(),
        };

        // extract DE public keys from did document -> Vec<&KeyPairs>
        // let doc: Document = serde_json::from_str(TEST_SIDETREE_DOCUMENT_MULTIPLE_KEYS).unwrap();
        // let test_keys_map = extract_key_ids_and_jwk(&doc).unwrap();
        let mut test_keys_map: HashMap<String, Jwk> = HashMap::new();
        test_keys_map.insert(
            String::from("key_1"),
            serde_json::from_str(DOWNSTREAM_PUB_KEY_1).unwrap(),
        );
        test_keys_map.insert(
            String::from("key_2"),
            serde_json::from_str(DOWNSTREAM_PUB_KEY_2).unwrap(),
        );

        // TODO: this should go in its own function
        let nonces: HashMap<String, String> =
            test_keys_map
                .iter()
                .fold(HashMap::new(), |mut acc, (key_id, _)| {
                    acc.insert(String::from(key_id), generate_nonce());
                    acc
                });

        for (key, val) in &nonces {
            println!("{}", val);
        }

        let challenges = nonces
            .iter()
            .fold(HashMap::new(), |mut acc, (key_id, nonce)| {
                acc.insert(
                    String::from(key_id),
                    encrypt(nonce.clone(), &test_keys_map.get(key_id).unwrap()).unwrap(),
                );
                acc
            });

        // sign (UE private key) and encrypt (DE temp public key) entire challenge
        let value: serde_json::Value = serde_json::to_value(challenges).unwrap();
        let mut payload = JwtPayload::new();
        payload.set_claim("challenges", Some(value)).unwrap();

        let encrypted_challenge = upstream_cr_keys.sign_and_encrypt(&payload).unwrap();

        // verify and decrypt
        let downstream_cr_keys = KeysCR {
            private_key: serde_json::from_str(TEMP_PRIVATE_KEY).unwrap(),
            public_key: serde_json::from_str(UPSTREAM_PUB_KEY).unwrap(),
        };
        let decrypted_challenge = downstream_cr_keys
            .decrypt_and_verify(encrypted_challenge)
            .unwrap();

        // extract challenge hashmap
        let challenges_hashmap: HashMap<String, String> =
            serde_json::from_value(decrypted_challenge.claim("challenges").unwrap().clone())
                .unwrap();

        // Decrypt each challenge nonce
        let mut test_priv_keys_map: HashMap<String, Jwk> = HashMap::new();
        test_priv_keys_map.insert(
            String::from("key_1"),
            serde_json::from_str(DOWNSTREAM_PRIV_KEY_1).unwrap(),
        );
        test_priv_keys_map.insert(
            String::from("key_2"),
            serde_json::from_str(DOWNSTREAM_PRIV_KEY_2).unwrap(),
        );

        // -----------------------------------------
        let response =
            generate_content_response(challenges_hashmap, test_priv_keys_map, &downstream_cr_keys)
                .unwrap();

        // UE: verify response
        let verified_response = verify_content_response(response, &upstream_cr_keys).unwrap();

        let nonce_1 = verified_response.get("key_1").unwrap();
        let expected_nonce_1 = nonces.get("key_1").unwrap();

        assert_eq!(
            verified_response.get("key_1").unwrap(),
            nonces.get("key_1").unwrap()
        );
        assert_eq!(
            verified_response.get("key_2").unwrap(),
            nonces.get("key_2").unwrap()
        );
    }
}
