use std::collections::HashMap;

use josekit::jwe::ECDH_ES;
use josekit::jwk::Jwk;
use josekit::jws::{JwsHeader, ES256K};
use josekit::jwt::{self, JwtPayload};
use serde_json::Value;
use ssi::did::{Document, VerificationMethod};
use ssi::jwk::JWK;

use crate::attestation_utils::TrustchainCRError;

pub struct Entity {}

impl SignEncrypt for Entity {}

impl DecryptVerify for Entity {}

/// Interface for signing and then encrypting data.
pub trait SignEncrypt {
    /// Cryptographically signs a payload with a secret key.
    fn sign(&self, payload: &JwtPayload, secret_key: &Jwk) -> Result<String, TrustchainCRError> {
        let mut header = JwsHeader::new();
        header.set_token_type("JWT");
        let signer = ES256K.signer_from_jwk(&secret_key)?;
        let signed_jwt = jwt::encode_with_signer(payload, &header, &signer)?;
        Ok(signed_jwt)
    }
    /// `JWTPayload` is a wrapped [`Map`](https://docs.rs/serde_json/1.0.79/serde_json/struct.Map.html)
    /// of claims.
    /// Cryptographically encrypts a payload with a public key.
    fn encrypt(&self, payload: &JwtPayload, public_key: &Jwk) -> Result<String, TrustchainCRError> {
        let mut header = josekit::jwe::JweHeader::new();
        header.set_token_type("JWT");
        header.set_content_encryption("A128CBC-HS256");
        header.set_content_encryption("A256GCM");

        let encrypter = ECDH_ES.encrypter_from_jwk(&public_key)?;
        let encrypted_jwt = jwt::encode_with_encrypter(payload, &header, &encrypter)?;
        Ok(encrypted_jwt)
    }
    /// Wrapper function for signing and encrypting a payload.
    fn sign_and_encrypt_claim(
        &self,
        payload: &JwtPayload,
        secret_key: &Jwk,
        public_key: &Jwk,
    ) -> Result<String, TrustchainCRError> {
        let signed_payload = self.sign(payload, secret_key)?;
        let mut claims = JwtPayload::new();
        claims.set_claim("claim", Some(Value::from(signed_payload)))?;
        self.encrypt(&claims, &public_key)
    }
}
/// Interface for decrypting and then verifying data.
trait DecryptVerify {
    /// Decrypts a payload with a secret key.
    fn decrypt(&self, value: &Value, secret_key: &Jwk) -> Result<JwtPayload, TrustchainCRError> {
        let decrypter = ECDH_ES.decrypter_from_jwk(&secret_key)?;
        let (payload, _) = jwt::decode_with_decrypter(value.as_str().unwrap(), &decrypter)?;
        Ok(payload)
    }
    /// Wrapper function that combines decrypting a payload with a secret key and then verifying it with a public key.
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

/// Converts key from josekit Jwk into ssi JWK
pub fn josekit_to_ssi_jwk(key: &Jwk) -> Result<JWK, serde_json::Error> {
    let key_as_str: &str = &serde_json::to_string(&key).unwrap();
    let ssi_key: JWK = serde_json::from_str(key_as_str).unwrap();
    Ok(ssi_key)
}
/// Converts key from ssi JWK into josekit Jwk
pub fn ssi_to_josekit_jwk(key: &JWK) -> Result<Jwk, serde_json::Error> {
    let key_as_str: &str = &serde_json::to_string(&key).unwrap();
    let ssi_key: Jwk = serde_json::from_str(key_as_str).unwrap();
    Ok(ssi_key)
}

/// Extracts public keys contained in DID document
pub fn extract_key_ids_and_jwk(
    document: &Document,
) -> Result<HashMap<String, Jwk>, TrustchainCRError> {
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
                    let key = vm_map
                        .get_jwk()
                        .map_err(|_| TrustchainCRError::MissingJWK)?;
                    let id = key
                        .thumbprint()
                        .map_err(|_| TrustchainCRError::MissingJWK)?;
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
    use super::*;
    use crate::data::{
        TEST_SIDETREE_DOCUMENT_MULTIPLE_KEYS, TEST_SIGNING_KEY_1, TEST_SIGNING_KEY_2,
        TEST_TEMP_KEY, TEST_UPDATE_KEY, TEST_UPSTREAM_KEY,
    };
    #[test]
    fn test_sign_encrypt_and_decrypt_verify() {
        let entity = Entity {};
        let mut payload = JwtPayload::new();
        payload
            .set_claim("test", Some(Value::from("This is a test claim.")))
            .unwrap();
        // encrypt and sign payload
        let secret_key_1: Jwk = serde_json::from_str(TEST_SIGNING_KEY_1).unwrap();
        let secret_key_2: Jwk = serde_json::from_str(TEST_SIGNING_KEY_2).unwrap();
        let public_key_1 = secret_key_1.to_public_key().unwrap();
        let public_key_2 = secret_key_2.to_public_key().unwrap();
        let signed_encrypted_payload = entity
            .sign_and_encrypt_claim(&payload, &secret_key_1, &public_key_2)
            .unwrap();
        // decrypt and verify payload
        let decrypted_verified_payload = entity
            .decrypt_and_verify(signed_encrypted_payload, &secret_key_2, &public_key_1)
            .unwrap();
        assert_eq!(
            decrypted_verified_payload
                .claim("test")
                .unwrap()
                .as_str()
                .unwrap(),
            "This is a test claim."
        );
    }

    #[test]
    fn test_extract_key_ids_and_jwk() {
        let document: Document =
            serde_json::from_str(TEST_SIDETREE_DOCUMENT_MULTIPLE_KEYS).unwrap();
        let key_ids_and_jwk = extract_key_ids_and_jwk(&document).unwrap();
        assert_eq!(key_ids_and_jwk.len(), 2);
    }
}
