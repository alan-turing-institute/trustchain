//! Utils module.
use serde::Serialize;
use sha2::{Digest, Sha256};
use ssi::did::{Document, VerificationMethod, VerificationMethodMap};
use ssi::jwk::JWK;
use std::path::{Path, PathBuf};
use std::sync::Once;
use trustchain_config::config;

// Set-up tempdir and use as env var for TRUSTCHAIN_DATA
// https://stackoverflow.com/questions/58006033/how-to-run-setup-code-before-any-tests-run-in-rust
static INIT: Once = Once::new();
pub fn init() {
    INIT.call_once(|| {
        // initialization code here
        let tempdir = tempfile::tempdir().unwrap();
        std::env::set_var(
            &config().core.trustchain_data,
            Path::new(tempdir.as_ref().as_os_str()),
        );
    });
}

/// Extracts a vec of public keys from a DID document.
pub fn extract_keys(doc: &Document) -> Vec<JWK> {
    let mut public_keys: Vec<JWK> = Vec::new();
    if let Some(verification_methods) = doc.verification_method.as_ref() {
        for verification_method in verification_methods {
            if let VerificationMethod::Map(VerificationMethodMap {
                public_key_jwk: Some(key),
                ..
            }) = verification_method
            {
                public_keys.push(key.clone());
            } else {
                continue;
            }
        }
    }
    public_keys
}

/// From [did-ion](https://docs.rs/did-ion/0.1.0/src/did_ion/sidetree.rs.html).
const MULTIHASH_SHA2_256_PREFIX: &[u8] = &[0x12];
/// From [did-ion](https://docs.rs/did-ion/0.1.0/src/did_ion/sidetree.rs.html).
const MULTIHASH_SHA2_256_SIZE: &[u8] = &[0x20];
/// From [did-ion](https://docs.rs/did-ion/0.1.0/src/did_ion/sidetree.rs.html#107-209).
/// Returns multihash prefix and hash.
///
/// Default implementation: SHA-256 (`sha2-256`)
fn hash_protocol_algorithm(data: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize().to_vec();
    (
        [MULTIHASH_SHA2_256_PREFIX, MULTIHASH_SHA2_256_SIZE].concat(),
        hash,
    )
}

/// [`DATA_ENCODING_SCHEME`](https://identity.foundation/sidetree/spec/v1.0.0/#data-encoding-scheme)
fn data_encoding_scheme(data: &[u8]) -> String {
    base64::encode_config(data, base64::URL_SAFE_NO_PAD)
}

/// Gets the path for storing operations and creates directories if they do not exist.
pub fn get_operations_path() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path: String = std::env::var(&config().core.trustchain_data)?;
    // Make directory and operation file name
    let path = Path::new(path.as_str()).join("operations");
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

/// Returns the suffix of a short-form DID.
pub fn get_did_suffix(did: &str) -> &str {
    did.split(':').last().unwrap()
}

/// [`JSON_CANONICALIZATION_SCHEME`](https://identity.foundation/sidetree/spec/v1.0.0/#json-canonicalization-scheme)
pub fn canonicalize<T: Serialize + ?Sized>(value: &T) -> Result<String, serde_json::Error> {
    serde_jcs::to_string(value)
}

/// From [did-ion](https://docs.rs/did-ion/0.1.0/src/did_ion/sidetree.rs.html).
/// [`HASH_PROTOCOL`](https://identity.foundation/sidetree/spec/v1.0.0/#hash-protocol)
///
/// Default implementation calls [hash_protocol_algorithm] and returns the concatenation of the
/// prefix and hash.
///
/// [hash_protocol_algorithm]: hash_protocol_algorithm
fn hash_protocol(data: &[u8]) -> Vec<u8> {
    let (prefix, hash) = hash_protocol_algorithm(data);
    [prefix, hash].concat()
}

/// Hash and encode data
///
/// [Sidetree §6.1 Hashing Process](https://identity.foundation/sidetree/spec/#hashing-process)
pub fn hash(data: &str) -> String {
    let hash = hash_protocol(data.as_bytes());
    data_encoding_scheme(&hash)
}

/// Extracts payload from JWT and verifies signature.
pub fn decode_verify(jwt: &str, key: &JWK) -> Result<String, ssi::error::Error> {
    ssi::jwt::decode_verify(jwt, key)
}

/// Extracts and decodes the payload from the JWT.
pub fn decode(jwt: &str) -> Result<String, ssi::error::Error> {
    ssi::jwt::decode_unverified(jwt)
}

/// Generates a new cryptographic key.
pub fn generate_key() -> JWK {
    JWK::generate_secp256k1().expect("Could not generate key.")
}

#[allow(dead_code)]
pub fn set_panic_hook() {
    // When the `console_error_panic_hook` feature is enabled, we can call the
    // `set_panic_hook` function at least once during initialization, and then
    // we will get better error messages if our code ever panics.
    //
    // For more details see
    // <https://github.com/rustwasm/console_error_panic_hook#readme>
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::{TEST_ROOT_JWK_PK, TEST_ROOT_PLUS_1_DOCUMENT, TEST_ROOT_PLUS_1_JWT};
    use ssi::did::Document;

    #[test]
    fn test_decode_verify() -> Result<(), Box<dyn std::error::Error>> {
        let key: JWK = serde_json::from_str(TEST_ROOT_JWK_PK)?;
        let jwt = TEST_ROOT_PLUS_1_JWT;
        let result = decode_verify(jwt, &key);
        assert!(result.is_ok());
        Ok(())
    }

    #[test]
    fn test_decode_canonicalize_hash() -> Result<(), Box<dyn std::error::Error>> {
        let doc: Document = serde_json::from_str(TEST_ROOT_PLUS_1_DOCUMENT)?;
        let doc_canon = canonicalize(&doc)?;
        let actual_hash = hash(&doc_canon);
        let jwt = TEST_ROOT_PLUS_1_JWT;
        let expected_hash = decode(jwt)?;
        assert_eq!(expected_hash, actual_hash);
        Ok(())
    }

    #[test]
    fn test_generate_key() {
        let result = generate_key();

        // Check for the expected elliptic curve (used by ION to generate keys).
        match result.params {
            ssi::jwk::Params::EC(ecparams) => {
                assert_eq!(ecparams.curve, Some(String::from("secp256k1")))
            }
            _ => panic!(),
        }
    }
}
