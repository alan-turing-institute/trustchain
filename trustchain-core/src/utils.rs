//! Utils module.
use serde::Serialize;
use sha2::{Digest, Sha256};
use ssi::jwk::JWK;
// use std::io::Read;
use crate::TRUSTCHAIN_DATA;
use std::path::{Path, PathBuf};
use std::sync::Once;

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

/// From did-ion: https://docs.rs/did-ion/0.1.0/src/did_ion/sidetree.rs.html
const MULTIHASH_SHA2_256_PREFIX: &[u8] = &[0x12];
const MULTIHASH_SHA2_256_SIZE: &[u8] = &[0x20];
/// From did-ion: https://docs.rs/did-ion/0.1.0/src/did_ion/sidetree.rs.html#107-209
/// Combination of [hash_protocol] and [hash_algorithm]
///
/// Returns multihash prefix and hash.
///
/// Default implementation: SHA-256 (`sha2-256`)
///
/// [hash_protocol] and [hash_algorithm] must correspond, and their default implementations
/// call this function ([hash_protocol_algorithm]). Implementers are therefore encouraged to
/// overwrite this function ([hash_protocol_algorithm]) rather than those ([hash_protocol] and
/// [hash_algorithm]).
///
/// [hash_protocol]: Self::hash_protocol
/// [hash_algorithm]: Self::hash_algorithm
/// [hash_protocol_algorithm]: Self::hash_protocol_algorithm
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

/// [`JSON_CANONICALIZATION_SCHEME`](https://identity.foundation/sidetree/spec/v1.0.0/#json-canonicalization-scheme)
pub fn canonicalize<T: Serialize + ?Sized>(value: &T) -> Result<String, serde_json::Error> {
    serde_jcs::to_string(value)
}

/// Generates a new cryptographic key.
pub fn generate_key() -> JWK {
    JWK::generate_secp256k1().expect("Could not generate key.")
}

/// [`HASH_PROTOCOL`](https://identity.foundation/sidetree/spec/v1.0.0/#hash-protocol)
///
/// This should be implemented using [hash_algorithm].
///
/// Default implementation calls [hash_protocol_algorithm] and returns the concatenation of the
/// prefix and hash.
///
/// This function must correspond with [hash_algorithm]. To ensure that correspondence,
/// implementers may want to override [hash_protocol_algorithm] instead of this function.
///
/// [hash_algorithm]: Self::hash_algorithm
/// [hash_protocol_algorithm]: Self::hash_protocol_algorithm
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

/// Tests whether one JSON object contains all the elements of another.
pub fn json_contains(candidate: &serde_json::Value, expected: &serde_json::Value) -> bool {
    match expected {
        serde_json::Value::Null => return true,
        serde_json::Value::Bool(x) => {
            if let serde_json::Value::Bool(y) = candidate {
                return x == y;
            } else {
                return false;
            }
        }
        serde_json::Value::Number(x) => {
            if let serde_json::Value::Number(y) = candidate {
                return x == y;
            } else {
                return false;
            }
        }
        serde_json::Value::String(x) => {
            if let serde_json::Value::String(y) = candidate {
                return x == y;
            } else {
                return false;
            }
        }
        serde_json::Value::Array(expected_vec) => {
            if let serde_json::Value::Array(candidate_vec) = candidate {
                // Check each element of the (expected) vector is contained in the
                // candidate vector, ignoring order.
                for exp in expected_vec {
                    if !candidate_vec.iter().any(|cand| json_contains(cand, exp)) {
                        return false;
                    }
                }
                return true;
            } else {
                return false;
            }
        }
        serde_json::Value::Object(expected_map) => {
            if let serde_json::Value::Object(candidate_map) = candidate {
                // Check each element of the (expected) map is contained in the
                // candidate vector.
                for exp_key in expected_map.keys() {
                    if !candidate_map.contains_key(exp_key) {
                        return false;
                    }
                    let expected_value = expected_map.get(exp_key).unwrap();
                    let candidate_value = candidate_map.get(exp_key).unwrap();
                    if !json_contains(candidate_value, expected_value) {
                        return false;
                    }
                }
                return true;
            } else {
                return false;
            }
        }
    }
}

#[allow(dead_code)]
pub fn set_panic_hook() {
    // When the `console_error_panic_hook` feature is enabled, we can call the
    // `set_panic_hook` function at least once during initialization, and then
    // we will get better error messages if our code ever panics.
    //
    // For more details see
    // https://github.com/rustwasm/console_error_panic_hook#readme
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
    use serde_json::to_string_pretty as to_json;
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
        let cand_str = r#"{"provisionalIndexFileUri":"QmfXAa2MsHspcTSyru4o1bjPQELLi62sr2pAKizFstaxSs","operations":{"create":[{"suffixData":{"deltaHash":"EiBkAX9y-Ts_siMzTzkfAzPKPIIbB033PlF0RlvF97ydJg","recoveryCommitment":"EiCymv17OGBAs7eLmm4BIXDCQBVhdOUAX5QdpIrN4SDE5w"}},{"suffixData":{"deltaHash":"EiBBkv0j587BDSTjJtIv2DJFOOHk662n9Uoh1vtBaY3JKA","recoveryCommitment":"EiClOaWycGv1m-QejUjB0L18G6DVFVeTQCZCuTRrmzCBQg"}},{"suffixData":{"deltaHash":"EiDTaFAO_ae63J4LMApAM-9VAo8ng58TTp2K-2r1nek6lQ","recoveryCommitment":"EiCy4pW16uB7H-ijA6V6jO6ddWfGCwqNcDSJpdv_USzoRA"}}]}}"#;
        let candidate: serde_json::Value = serde_json::from_str(cand_str).unwrap();

        let exp_str =
            r#"{"provisionalIndexFileUri":"QmfXAa2MsHspcTSyru4o1bjPQELLi62sr2pAKizFstaxSs"}"#;
        let expected: serde_json::Value = serde_json::from_str(exp_str).unwrap();
        assert!(json_contains(&candidate, &expected));

        // Test with different key.
        let exp_str =
            r#"{"provisionalIndeXFileUri":"QmfXAa2MsHspcTSyru4o1bjPQELLi62sr2pAKizFstaxSs"}"#;
        let expected: serde_json::Value = serde_json::from_str(exp_str).unwrap();
        assert!(!json_contains(&candidate, &expected));

        // Test with different value.
        let exp_str =
            r#"{"provisionalIndexFileUri":"PmfXAa2MsHspcTSyru4o1bjPQELLi62sr2pAKizFstaxSs"}"#;
        let expected: serde_json::Value = serde_json::from_str(exp_str).unwrap();
        assert!(!json_contains(&candidate, &expected));

        // Test with JSON arrays.
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
    }
}
