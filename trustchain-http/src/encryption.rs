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
    // should the struct be public?
    temp_pub_key: String,
    upstream_priv_key: String,
    nonce: String,
    update_commitment: String,
}

// const temp_private_key: &str = r#"{"crv":"secp256k1","x":"JokHTNHd1lIw2EXUTV1RJL3wvWMgoIRHPaWxTHcyH9U","y":"z737jJY7kxW_lpE1eZur-9n9_HUEGFyBGsTdChzI4Kg","d":"CfdUwQ-CcBQkWpIDPjhSJAq2SCg6hAGdcvLmCj0aA-c"}"#;
// const temp_pub_key: &str = r#"{"crv":"secp256k1","x":"JokHTNHd1lIw2EXUTV1RJL3wvWMgoIRHPaWxTHcyH9U","y":"z737jJY7kxW_lpE1eZur-9n9_HUEGFyBGsTdChzI4Kg"}"#;
fn generate_nonce() -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}

/// Example of step 2 of CR Part I: Identity CR.
fn example() -> Result<(), JoseError> {
    let challenge = IdentityChallenge {
        temp_pub_key: String::from(TEMP_PUB_KEY),
        upstream_priv_key: String::from(UPSTREAM_PRIVATE_KEY),
        nonce: generate_nonce(),
        update_commitment: String::from("placeholderupdatecommitment"),
    };

    let mut header = JweHeader::new();
    header.set_token_type("JWT");
    // header.set_content_encryption("A128CBC-HS256");
    header.set_content_encryption("A256GCM");

    let mut payload = JwtPayload::new();
    payload.set_claim("nonce", Some(Value::from(challenge.nonce)))?;
    payload.set_claim(
        "update_commitment",
        Some(Value::from(challenge.update_commitment)),
    )?;

    // Encrypting JWT
    let temp_pub_key_jwk: Jwk = serde_json::from_str(&challenge.temp_pub_key).unwrap();
    let encrypter_from_jwk = ECDH_ES.encrypter_from_jwk(&temp_pub_key_jwk)?;
    let jwt = jwt::encode_with_encrypter(&payload, &header, &encrypter_from_jwk)?;
    println!("JWT: {}", jwt);

    // Signing JWT that contains encrypted nonce
    // TODO: add update commitment
    let mut header = JwsHeader::new();
    header.set_token_type("JWT");

    let mut payload = JwtPayload::new();
    payload.set_claim("encrypted_nonce", Some(Value::from(jwt)))?;
    let upstream_private_key_jwk: Jwk = serde_json::from_str(&challenge.upstream_priv_key).unwrap();
    let signer = ES256K.signer_from_jwk(&upstream_private_key_jwk)?;
    let jwt = jwt::encode_with_signer(&payload, &header, &signer)?;

    // Verifying signature JWT
    let upstream_public_key_jwk: Jwk = serde_json::from_str(&UPSTREAM_PUB_KEY).unwrap();
    let verifier = ES256K.verifier_from_jwk(&upstream_public_key_jwk)?;
    // let verifier = ES256K.verifier_from_jwk(&temp_pub_key_jwk)?; // this should fail -> wrong key
    let (payload, header) = jwt::decode_with_verifier(&jwt, &verifier)?;

    // // Decrypting JWT
    let temp_private_key_jwk: Jwk = serde_json::from_str(&TEMP_PRIVATE_KEY).unwrap();
    let decrypter_from_jwk = ECDH_ES.decrypter_from_jwk(&temp_private_key_jwk)?;
    let encrypted_nonce = payload.claim("encrypted_nonce").unwrap().as_str().unwrap();
    let (payload, header) = jwt::decode_with_decrypter(encrypted_nonce, &decrypter_from_jwk)?;
    println!("Header: {}", header);
    println!("Payload: {}", payload);
    Ok(())
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

#[cfg(test)]
mod tests {
    use sha2::digest::typenum::private::IsEqualPrivate;

    use super::*;
    #[test]
    fn test_example() {
        example().unwrap();
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
    // #[test]
    // fn test_ec_key() {
    //     let key = Jwk::generate_ec_key(josekit::jwk::alg::ec::EcCurve::Secp256k1).unwrap();
    //     println!("{}", serde_json::to_string_pretty(&key).unwrap());
    // }
}
