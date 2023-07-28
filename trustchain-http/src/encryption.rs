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
use serde_json::Value;
use ssi::jwk::JWK;

use crate::errors::TrustchainHTTPError;

const TEMP_PRIVATE_KEY: &str = r#"{"kty":"EC","crv":"secp256k1","x":"JokHTNHd1lIw2EXUTV1RJL3wvWMgoIRHPaWxTHcyH9U","y":"z737jJY7kxW_lpE1eZur-9n9_HUEGFyBGsTdChzI4Kg","d":"CfdUwQ-CcBQkWpIDPjhSJAq2SCg6hAGdcvLmCj0aA-c"}"#;
const TEMP_PUB_KEY: &str = r#"{"kty":"EC","crv":"secp256k1","x":"JokHTNHd1lIw2EXUTV1RJL3wvWMgoIRHPaWxTHcyH9U","y":"z737jJY7kxW_lpE1eZur-9n9_HUEGFyBGsTdChzI4Kg"}"#;
const UPSTREAM_PRIVATE_KEY: &str = r#"{"kty":"EC","crv":"secp256k1","x":"JEV4WMgoJekTa5RQD5M92P1oLjdpMNYETQ3nbtKSnLQ","y":"dRfg_5i5wcMg1lxAffQORHpzgtm2yEIqgJoUk5ZklvI","d":"DZDZd9bxopCv2YJelMpQm_BJ0awvzpT6xWdWbaQlIJI"}"#;
const UPSTREAM_PUB_KEY: &str = r#"{"kty":"EC","crv":"secp256k1","x":"JEV4WMgoJekTa5RQD5M92P1oLjdpMNYETQ3nbtKSnLQ","y":"dRfg_5i5wcMg1lxAffQORHpzgtm2yEIqgJoUk5ZklvI"}"#;

pub struct IdentityChallenge {
    nonce: String,
    update_commitment: String,
}

pub struct KeysCR {
    private_key: Jwk,
    public_key: Jwk,
}

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

/// Generates the components required for identity challenge part of challenge response protocol
fn generate_challenge() {
    // generate nonce
    // get update commitment
    todo!()
}

fn present_challenge(challenge: &IdentityChallenge, keys: &KeysCR) -> Result<String, JoseError> {
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
    fn test_present_challenge_and_response() {
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
        let presented_challenge = present_challenge(&test_challenge, &upstream_cr_keys).unwrap();

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

    // #[test]
    // fn test_ec_key() {
    //     let key = Jwk::generate_ec_key(josekit::jwk::alg::ec::EcCurve::Secp256k1).unwrap();
    //     println!("{}", serde_json::to_string_pretty(&key).unwrap());
    // }
}
