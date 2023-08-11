use josekit::jwe::{JweHeader, ECDH_ES};
use josekit::jwk::Jwk;
use josekit::jws::{JwsHeader, ES256K};
use josekit::jwt::{self, JwtPayload};
use josekit::JoseError;
use rand::rngs::StdRng;
use rand::{distributions::Alphanumeric, Rng, SeedableRng};
use serde_json::Value;
use std::collections::HashMap;
use thiserror::Error;
use trustchain_core::key_manager::{KeyManager, KeyType};
use trustchain_core::subject::Subject;

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
    /// Claim not found in JWTPayload
    #[error("Claim not found in JWTPayload.")]
    ClaimNotFound,
}

impl From<JoseError> for TrustchainCRError {
    fn from(err: JoseError) -> Self {
        Self::Jose(err)
    }
}

struct UpstreamState {} // same as Downstream?

// struct DownstreamState{}

struct CRInitiation {
    temp_p_key: Jwk,
    requester_org: String,
    operator_name: String,
}

struct CRIdentityChallenge {
    update_p_key: Jwk,
    identity_nonce: String, // make own Nonce type
                            // field for the signed and encrypted challenge?
}

impl TryFrom<CRIdentityChallenge> for JwtPayload {
    type Error = TrustchainCRError;
    fn try_from(value: CRIdentityChallenge) -> Result<Self, Self::Error> {
        let mut payload = JwtPayload::new();
        payload.set_claim("identity_nonce", Some(Value::from(value.identity_nonce)))?;
        // Todo: add update_p_key
        Ok(payload)
    }
}

/// Interface for signing and then encrypting data.
trait SignEncrypt {
    fn sign(&self, payload: &JwtPayload, secret_key: Jwk) -> Result<String, TrustchainCRError> {
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
        secret_key: Jwk,
        public_key: Jwk,
    ) -> Result<String, TrustchainCRError> {
        let signed_encoded_payload = self.sign(payload, secret_key)?;
        // make payload of claims to encrypt
        let mut claims = JwtPayload::new();
        claims.set_claim("claim", Some(Value::from(signed_encoded_payload)))?;
        self.encrypt(&claims, &public_key)
    }
}
/// Interface for decrypting and then verify data.
trait DecryptVerify {
    // fn decrypt
    // fn verify
    // fn decrypt_and_verify
}

struct MyType {
    foo: String,
}

impl TryFrom<JwtPayload> for MyType {
    type Error = TrustchainCRError;
    fn try_from(value: JwtPayload) -> Result<Self, Self::Error> {
        let x = value.claim("foo").ok_or(TrustchainCRError::ClaimNotFound)?;
        Ok(Self { foo: x.to_string() })
    }
}

// impl From<JwtPayload> for MyType {
//     fn from(value: JwtPayload) -> Self {
//         let x = value.claim("foo").unwrap();
//         Self { foo: x.to_string() }
//     }
// }

// impl From<MyType> for JwtPayload {
//     fn from(value: MyType) -> Self {}
// }

///  Generates a random alphanumeric nonce of a specified length using a seeded random number generator.
fn generate_nonce(seed: u64) -> String {
    let rng: StdRng = SeedableRng::seed_from_u64(seed);
    rng.sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}

fn present_identity_challenge() {
    todo!()
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_generate_nonce() {
        let expected_nonce = String::from("IhPi3oZCnaWvL2oIeA07mg3ZtJzh0NoA");
        let nonce = generate_nonce(42);
        assert_eq!(nonce, expected_nonce)
    }
}
