use std::str::FromStr;

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
use serde_json::Value;
use sha2::{Digest, Sha256};
use ssi::jwk::JWK;

const TEMP_PRIVATE_KEY: &str = r#"{"kty":"EC","crv":"secp256k1","x":"JokHTNHd1lIw2EXUTV1RJL3wvWMgoIRHPaWxTHcyH9U","y":"z737jJY7kxW_lpE1eZur-9n9_HUEGFyBGsTdChzI4Kg","d":"CfdUwQ-CcBQkWpIDPjhSJAq2SCg6hAGdcvLmCj0aA-c"}"#;
const TEMP_PUB_KEY: &str = r#"{"kty":"EC","crv":"secp256k1","x":"JokHTNHd1lIw2EXUTV1RJL3wvWMgoIRHPaWxTHcyH9U","y":"z737jJY7kxW_lpE1eZur-9n9_HUEGFyBGsTdChzI4Kg"}"#;
const UPSTREAM_PRIVATE_KEY: &str = r#"{"kty":"EC","crv":"secp256k1","x":"JEV4WMgoJekTa5RQD5M92P1oLjdpMNYETQ3nbtKSnLQ","y":"dRfg_5i5wcMg1lxAffQORHpzgtm2yEIqgJoUk5ZklvI","d":"DZDZd9bxopCv2YJelMpQm_BJ0awvzpT6xWdWbaQlIJI"}"#;
const UPSTREAM_PUB_KEY: &str = r#"{"kty":"EC","crv":"secp256k1","x":"JEV4WMgoJekTa5RQD5M92P1oLjdpMNYETQ3nbtKSnLQ","y":"dRfg_5i5wcMg1lxAffQORHpzgtm2yEIqgJoUk5ZklvI"}"#;
const DOWNSTREAM_PRIV_KEY_1: &str = r#"{"kty":"EC","crv":"secp256k1","x":"Lt2ys7LE0ELccVtCETtVjMFavgjwYDjDBtuV_XCH7-g","y":"TdTT8oXUSXMvFbhnsYrqwOkL7-niHWFxW0vaBSnUMnI","d":"B7csdham680yGiIdxeyllmczap7-h6_LtKunRhRqfic"}"#;
const DOWNSTREAM_PUB_KEY_1: &str = r#"{"kty":"EC","crv":"secp256k1","x":"Lt2ys7LE0ELccVtCETtVjMFavgjwYDjDBtuV_XCH7-g","y":"TdTT8oXUSXMvFbhnsYrqwOkL7-niHWFxW0vaBSnUMnI"}"#;
const DOWNSTREAM_PRIV_KEY_2: &str = r#"{"kty":"EC","crv":"secp256k1","x":"AB1b_4-XSem0uiPGGuW_hf_AuPArukMuD2S95ypGDSE","y":"suvBnCbhicPdYZeqgxJfPFmiNHGYDjPiW8XkYHxwgBU","d":"V3zmieRjP9LYa1v8l8lYXh4LqU87bPspSAGqq34Up1Q"}"#;
const DOWNSTREAM_PUB_KEY_2: &str = r#"{"kty":"EC","crv":"secp256k1","x":"AB1b_4-XSem0uiPGGuW_hf_AuPArukMuD2S95ypGDSE","y":"suvBnCbhicPdYZeqgxJfPFmiNHGYDjPiW8XkYHxwgBU"}"#;

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

// trait Encryption { ??
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

#[cfg(test)]
mod tests {
    use sha2::digest::typenum::private::IsEqualPrivate;

    use super::*;

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
        // keys we need
        let upstream_cr_keys = KeysCR {
            private_key: serde_json::from_str(UPSTREAM_PRIVATE_KEY).unwrap(),
            public_key: serde_json::from_str(TEMP_PUB_KEY).unwrap(),
        };

        // TODO: extract public keys from did document -> Vec<&KeyPairs>
        let mut downstream_keys = Vec::<&Jwk>::new();
        let downstream_pub_key_1: Jwk = serde_json::from_str(DOWNSTREAM_PUB_KEY_1).unwrap();
        let downstream_pub_key_2: Jwk = serde_json::from_str(DOWNSTREAM_PUB_KEY_2).unwrap();
        downstream_keys.push(&downstream_pub_key_1);
        downstream_keys.push(&downstream_pub_key_2);

        // generate one nonce per public key -> sign individually (vec of signed nonces)
        let challenge_vec: Vec<String> = downstream_keys
            .iter()
            .map(|key| generate_challenge(key).unwrap())
            .collect();

        let key_hash_vec: Vec<String> = downstream_keys
            .iter()
            .map(|key| hex::encode(Sha256::digest(serde_json::to_string(&key).unwrap())))
            .collect();

        println!("Vector with key hashes: {:?}", key_hash_vec);

        // sign (UE private key) and encrypt (DE temp public key) entire challenge
        let mut payload = JwtPayload::new();
        payload
            .set_claim("challenge", Some(Value::from(challenge_vec)))
            .unwrap();
        payload
            .set_claim("key_hash", Some(Value::from(key_hash_vec)))
            .unwrap();
        let encrypted_challenge = upstream_cr_keys.sign_and_encrypt(&payload).unwrap();

        // generate response
        // verify and decrypt -> extract vectors with challenges and key hashes
        let downstream_cr_keys = KeysCR {
            private_key: serde_json::from_str(TEMP_PRIVATE_KEY).unwrap(),
            public_key: serde_json::from_str(UPSTREAM_PUB_KEY).unwrap(),
        };
        let decrypted_challenge = downstream_cr_keys
            .decrypt_and_verify(encrypted_challenge)
            .unwrap();

        // extract vector with challenge nonce(s)
        let challenge_vec = decrypted_challenge
            .claim("challenge")
            .unwrap()
            .as_array()
            .unwrap();

        // private keys
        let mut downstream_private_keys = Vec::<&Jwk>::new();
        let downstream_private_key_1: Jwk = serde_json::from_str(DOWNSTREAM_PRIV_KEY_1).unwrap();
        let downstream_private_key_2: Jwk = serde_json::from_str(DOWNSTREAM_PRIV_KEY_2).unwrap();
        downstream_private_keys.push(&downstream_private_key_1);
        downstream_private_keys.push(&downstream_private_key_2);

        // decrypt each nonce
        let response_vec: Vec<JwtPayload> = challenge_vec
            .iter()
            .zip(downstream_private_keys.iter())
            .map(|(nonce, key)| decrypt(&nonce, &key).unwrap())
            .collect();
        println!("Decrypted challenge vector: {:?}", response_vec);
        // continue here!!!!!!!!!!!!! How do we find the right key for each nonce?

        // TODO: prepare response

        // TODO: verify response (nonces)
    }

    // #[test]
    // fn test_ec_key() {
    //     let key = Jwk::generate_ec_key(josekit::jwk::alg::ec::EcCurve::Secp256k1).unwrap();
    //     println!("{}", serde_json::to_string_pretty(&key).unwrap());
    // }
}
