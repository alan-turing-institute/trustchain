//! Utils module.
use crate::TRUSTCHAIN_DATA;
use serde::Serialize;
use sha2::{Digest, Sha256};
use ssi::did::{Document, ServiceEndpoint, VerificationMethod, VerificationMethodMap};
use ssi::jwk::JWK;
use std::path::{Path, PathBuf};
use std::sync::Once;

// Get the type of an object as a String. For diagnostic purposes (debugging) only.
pub fn type_of<T>(_: &T) -> String {
    std::any::type_name::<T>().to_string()
}

// Set-up tempdir and use as env var for TRUSTCHAIN_DATA
// https://stackoverflow.com/questions/58006033/how-to-run-setup-code-before-any-tests-run-in-rust
static INIT: Once = Once::new();
pub fn init() {
    INIT.call_once(|| {
        // initialization code here
        let tempdir = tempfile::tempdir().unwrap();
        std::env::set_var(TRUSTCHAIN_DATA, Path::new(tempdir.as_ref().as_os_str()));
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
    let path: String = std::env::var(TRUSTCHAIN_DATA)?;
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

pub trait HasKeys {
    fn get_keys(&self) -> Option<Vec<JWK>>;
}

pub trait HasEndpoints {
    fn get_endpoints(&self) -> Option<Vec<ServiceEndpoint>>;
}

impl HasKeys for Document {
    fn get_keys(&self) -> Option<Vec<JWK>> {
        let verification_methods = match &self.verification_method {
            Some(x) => x,
            None => return None,
        };

        let verification_method_maps: Vec<&VerificationMethodMap> = verification_methods
            .iter()
            .filter_map(|verification_method| match verification_method {
                VerificationMethod::Map(x) => Some(x),
                _ => {
                    eprintln!("Unhandled VerificationMethod variant. Expected Map.");
                    return None;
                }
            })
            .collect();

        if verification_method_maps.len() == 0 {
            return None;
        }

        let keys: Vec<JWK> = verification_method_maps
            .iter()
            .filter_map(|verification_method_map| verification_method_map.public_key_jwk.to_owned())
            .collect();

        if keys.len() == 0 {
            return None;
        }
        Some(keys)
    }
}

impl HasEndpoints for Document {
    fn get_endpoints(&self) -> Option<Vec<ServiceEndpoint>> {
        let services = match &self.service {
            Some(x) => x,
            None => return None,
        };
        let service_endpoints: Vec<ServiceEndpoint> = services
            .iter()
            .flat_map(|service| match service.to_owned().service_endpoint {
                Some(endpoints) => return endpoints.into_iter(),
                None => return Vec::<ServiceEndpoint>::new().into_iter(),
            })
            .collect();
        if service_endpoints.len() == 0 {
            return None;
        }
        Some(service_endpoints)
    }
}

/// Tests whether one JSON object contains all the elements of another.
pub fn json_contains(candidate: &serde_json::Value, expected: &serde_json::Value) -> bool {
    // If the expected Value is an array, recursively check each element.
    match expected {
        serde_json::Value::Array(exp_vec) => {
            return exp_vec
                .iter()
                .all(|exp_value| json_contains(candidate, exp_value))
        }
        _ => (),
    }
    match candidate {
        serde_json::Value::Null => matches!(expected, serde_json::Value::Null),
        serde_json::Value::Bool(x) => match expected {
            serde_json::Value::Bool(y) => x == y,
            _ => false,
        },
        serde_json::Value::Number(x) => match expected {
            serde_json::Value::Number(y) => x == y,
            _ => false,
        },
        serde_json::Value::String(x) => match expected {
            serde_json::Value::String(y) => x == y,
            _ => false,
        },
        serde_json::Value::Array(cand_vec) => {
            // If the candidate is an Array, check if any value in the candidate contains the expected one.
            return cand_vec.iter().any(|value| json_contains(value, expected));
        }
        serde_json::Value::Object(cand_map) => {
            match expected {
                serde_json::Value::Object(exp_map) => {
                    // If both candidate and expected are Maps, check each element
                    // of the expected map is contained in the candidate map.
                    for exp_key in exp_map.keys() {
                        if !cand_map.contains_key(exp_key) {
                            // If the key is not found but the Value is itself a Map or Vector, recurse.
                            if cand_map.keys().any(|cand_key| {
                                if matches!(
                                    cand_map.get(cand_key).unwrap(),
                                    serde_json::Value::Object(..)
                                ) {
                                    return json_contains(
                                        cand_map.get(cand_key).unwrap(),
                                        expected,
                                    );
                                }
                                if matches!(
                                    cand_map.get(cand_key).unwrap(),
                                    serde_json::Value::Array(..)
                                ) {
                                    return json_contains(
                                        cand_map.get(cand_key).unwrap(),
                                        expected,
                                    );
                                }
                                return false;
                            }) {
                                return true;
                            };
                            return false;
                        }
                        let exp_value = exp_map.get(exp_key).unwrap();
                        let cand_value = cand_map.get(exp_key).unwrap();
                        if !json_contains(cand_value, exp_value) {
                            return false;
                        }
                    }
                    true
                }
                _ => {
                    // If the candidate is a Map and the expected is
                    // a scalar, check each value inside the candidate map.
                    return cand_map
                        .values()
                        .any(|cand_value| json_contains(cand_value, expected));
                }
            }
        }
    }
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
    use crate::data::{
        TEST_ROOT_JWK_PK, TEST_ROOT_PLUS_1_DOCUMENT, TEST_ROOT_PLUS_1_JWT,
        TEST_SIDETREE_DOCUMENT_MULTIPLE_KEYS,
    };
    use ssi::did::Document;

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
    fn test_json_contains() {
        // Test with a JSON map.
        let cand_str = r#"{"provisionalIndexFileUri":"QmfXAa2MsHspcTSyru4o1bjPQELLi62sr2pAKizFstaxSs","operations":{"create":[{"suffixData":{"deltaHash":"EiBkAX9y-Ts_siMzTzkfAzPKPIIbB033PlF0RlvF97ydJg","recoveryCommitment":"EiCymv17OGBAs7eLmm4BIXDCQBVhdOUAX5QdpIrN4SDE5w"}},{"suffixData":{"deltaHash":"EiBBkv0j587BDSTjJtIv2DJFOOHk662n9Uoh1vtBaY3JKA","recoveryCommitment":"EiClOaWycGv1m-QejUjB0L18G6DVFVeTQCZCuTRrmzCBQg"}},{"suffixData":{"deltaHash":"EiDTaFAO_ae63J4LMApAM-9VAo8ng58TTp2K-2r1nek6lQ","recoveryCommitment":"EiCy4pW16uB7H-ijA6V6jO6ddWfGCwqNcDSJpdv_USzoRA"}}]}}"#;
        let candidate: serde_json::Value = serde_json::from_str(cand_str).unwrap();

        let exp_str =
            r#"{"provisionalIndexFileUri":"QmfXAa2MsHspcTSyru4o1bjPQELLi62sr2pAKizFstaxSs"}"#;
        let expected: serde_json::Value = serde_json::from_str(exp_str).unwrap();
        assert!(json_contains(&candidate, &expected));

        // Different key.
        let exp_str =
            r#"{"provisionalIndeXFileUri":"QmfXAa2MsHspcTSyru4o1bjPQELLi62sr2pAKizFstaxSs"}"#;
        let expected: serde_json::Value = serde_json::from_str(exp_str).unwrap();
        assert!(!json_contains(&candidate, &expected));

        // Different value.
        let exp_str =
            r#"{"provisionalIndexFileUri":"PmfXAa2MsHspcTSyru4o1bjPQELLi62sr2pAKizFstaxSs"}"#;
        let expected: serde_json::Value = serde_json::from_str(exp_str).unwrap();
        assert!(!json_contains(&candidate, &expected));

        // Test with a JSON array.
        let array_vec = vec!["x".to_string(), "y".to_string(), "z".to_string()];
        let candidate = serde_json::json!(array_vec);
        assert!(json_contains(&candidate, &serde_json::json!("x")));
        assert!(json_contains(&candidate, &serde_json::json!("y")));
        assert!(json_contains(&candidate, &serde_json::json!("z")));
        assert!(!json_contains(&candidate, &serde_json::json!("X")));

        // Test with a JSON map containing a JSON array.
        let candidate: serde_json::Value =
            serde_json::from_str(TEST_SIDETREE_DOCUMENT_MULTIPLE_KEYS).unwrap();

        // Same elements but different order:
        let exp_str = r##"{"verificationMethod" : [
        {
            "controller" : "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9ZQ",
            "id" : "#V9jt_0c-aFlq40Uti2R_WiquxuzxyB8kn1cfWmXIU85",
            "publicKeyJwk" : {
                "crv": "secp256k1",
                "kty": "EC",
                "x": "7ReQHHysGxbyuKEQmspQOjL7oQUqDTldTHuc9V3-yso",
                "y": "kWvmS7ZOvDUhF8syO08PBzEpEk3BZMuukkvEJOKSjqE"
            },
            "type" : "JsonWebSignature2020"
        },
        {
            "controller" : "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9ZQ",
            "id" : "#V8jt_0c-aFlq40Uti2R_WiquxuzxyB8kn1cfWmXIU84",
            "publicKeyJwk" : {
                "crv" : "secp256k1",
                "kty" : "EC",
                "x" : "RbIj1Y4jeqkn0cizEfxHZidD-GQouFmAtE6YCpxFjpg",
                "y" : "ZcbgNp3hrfp3cujZFKqgFS0uFGOn2Rk16Y9nOv0h15s"
            },
            "type" : "JsonWebSignature2020"
        }]
    }"##;
        let expected: serde_json::Value = serde_json::from_str(exp_str).unwrap();
        assert!(json_contains(&candidate, &expected));

        // Different nested key:
        let exp_str = r##"{"verificationMethod" : [
        {
            "controller" : "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9ZQ",
            "id" : "#V9jt_0c-aFlq40Uti2R_WiquxuzxyB8kn1cfWmXIU85",
            "publicKeyJwk" : {
                "crv": "secp256k1",
                "kty": "EC",
                "x": "7ReQHHysGxbyuKEQmspQOjL7oQUqDTldTHuc9V3-yso",
                "z": "kWvmS7ZOvDUhF8syO08PBzEpEk3BZMuukkvEJOKSjqE"
            },
            "type" : "JsonWebSignature2020"
        },
        {
            "controller" : "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9ZQ",
            "id" : "#V8jt_0c-aFlq40Uti2R_WiquxuzxyB8kn1cfWmXIU84",
            "publicKeyJwk" : {
                "crv" : "secp256k1",
                "kty" : "EC",
                "x" : "RbIj1Y4jeqkn0cizEfxHZidD-GQouFmAtE6YCpxFjpg",
                "y" : "ZcbgNp3hrfp3cujZFKqgFS0uFGOn2Rk16Y9nOv0h15s"
            },
            "type" : "JsonWebSignature2020"
        }]
    }"##;
        let expected: serde_json::Value = serde_json::from_str(exp_str).unwrap();
        assert!(!json_contains(&candidate, &expected));

        // Different nested value:
        let exp_str = r##"{"verificationMethod" : [
        {
            "controller" : "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9ZQ",
            "id" : "#V9jt_0c-aFlq40Uti2R_WiquxuzxyB8kn1cfWmXIU85",
            "publicKeyJwk" : {
                "crv": "secp256k1",
                "kty": "EC",
                "x": "7ReQHHysGxbyuKEQmspQOjL7oQUqDTldTHuc9V3-yso",
                "y": "kWvmS7ZOvDUhF8syO08PBzEpEk3BZMuukkvEJOKSjqE"
            },
            "type" : "JsonWebSignature2020"
        },
        {
            "controller" : "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9ZQ",
            "id" : "#V8jt_0c-aFlq40Uti2R_WiquxuzxyB8kn1cfWmXIU84",
            "publicKeyJwk" : {
                "crv" : "secp256k1",
                "kty" : "EC",
                "x" : "RbIj1Y4jeqkn0cizEfxHZidD-GQouFmAtE6YCpxFjpg",
                "y" : "YcbgNp3hrfp3cujZFKqgFS0uFGOn2Rk16Y9nOv0h15s"
            },
            "type" : "JsonWebSignature2020"
        }]
    }"##;

        let expected: serde_json::Value = serde_json::from_str(exp_str).unwrap();
        assert!(!json_contains(&candidate, &expected));

        // Entire expected object nested:
        let exp_str = r##"{"publicKeyJwk" : {
        "crv": "secp256k1",
        "kty": "EC",
        "x": "7ReQHHysGxbyuKEQmspQOjL7oQUqDTldTHuc9V3-yso",
        "y": "kWvmS7ZOvDUhF8syO08PBzEpEk3BZMuukkvEJOKSjqE"
    }}"##;

        let expected: serde_json::Value = serde_json::from_str(exp_str).unwrap();
        assert!(json_contains(&candidate, &expected));
    }
}
