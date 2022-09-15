use std::collections::HashMap;

use did_ion::sidetree::Sidetree;
use did_ion::ION;
use ssi::one_or_many::OneOrMany;
use ssi::jwk::{Base64urlUInt, ECParams, Params, JWK};
use thiserror::Error;

/// An error relating to Trustchain key management.
#[derive(Error, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum KeyManagerError {
    #[error("Key does not exist.")]
    FailToLoadKey,
}

/// KeyType enum.
#[derive(Debug, PartialEq, Eq, Hash)]
pub enum KeyType {
    UpdateKey,
    RecoveryKey,
    SigningKey,
}

/// Generates a new cryptographic key.
pub fn generate_key() -> JWK {
    ION::generate_key().expect("Could not generate key.")
}

/// Generates a set of update, recovery and signing keys.
pub fn generate_keys() -> HashMap<KeyType, OneOrMany<JWK>> {

    let update_key = generate_key();
    let recovery_key = generate_key();
    let signing_key = generate_key();

    let mut map = HashMap::new();
    map.insert(KeyType::UpdateKey, OneOrMany::One(update_key));
    map.insert(KeyType::RecoveryKey, OneOrMany::One(recovery_key));
    map.insert(KeyType::SigningKey, OneOrMany::One(signing_key));
    map
}

/// Reads a set of update, recovery and signing keys from disk.
pub fn read_keys(did: &str) -> Result<HashMap<KeyType, OneOrMany<JWK>>, KeyManagerError> {
    todo!()
}

/// Reads an update key from disk.
fn read_update_key(did: &str) -> Result<JWK, KeyManagerError> {
    todo!()
}

/// Reads a recovery key from disk.
fn read_recovery_key(did: &str) -> Result<JWK, KeyManagerError> {
    todo!()
}

/// Reads one or more signing keys from disk.
fn read_signing_keys(did: &str) -> Result<OneOrMany<JWK>, KeyManagerError> {
    todo!()
}

/// Saves a key to disk.
pub fn save_key(did: &str, key_type: KeyType, key: &JWK) -> () {
    todo!()
}

// fn load_key(did: &str) {
//     // Load previous data
//     let file_name = format!("update_{}", did);
//     let ec_read = std::fs::read(file_name).unwrap();
//     let ec_read = std::str::from_utf8(&ec_read).unwrap();
//     let ec_params: ECParams = serde_json::from_str(ec_read).unwrap();

//     // let ec_params = Params::EC(ec_params);
//     let update_key = JWK::from(Params::EC(ec_params));
//     println!("Valid key: {}", ION::validate_key(&update_key).is_ok());
//     // update_key
//     todo!()
// }

#[cfg(test)]
mod tests {
    // use did_ion::sidetree::Sidetree;
    // use serde_json::to_string_pretty as to_json;

    use super::*;

    const TEST_SIGNING_KEY: &str = r##"{
        "kty": "EC",
        "crv": "secp256k1",
        "x": "rHaN35OWWa4FHoqy41KTgv4Dtnjx9ux3VOV1ijdt0Wk",
        "y": "BG2EoOfbfeHrajlcQSXCQCK7wf-jxYRIyHt6Fj7QuZA",
        "d": "_YDaFkuim9AcB8Seh8wRMH35WGNcEH7D3w8A_HFC0lU"
    }"##;

    const TEST_UPDATE_KEY: &str = r##"{
        "kty": "EC",
        "crv": "secp256k1",
        "x": "2hm19BwmXmR8Vfuw2XbGrusm89Pg6dyExlzDfc-CiM8",
        "y": "uFjW0fKdhHaY4c_5E9Wkk3cPi9sJ5rP3oyl1ssV_X6A",
        "d": "Z2vJqNRjbWvJX2NzABKlHI2V00HWmV2KNI5P4mmxRbg"
    }"##;

    const TEST_RECOVERY_KEY: &str = r##"{
        "kty": "EC",
        "crv": "secp256k1",
        "x": "_Z1JRmGwvj0jIpDW-QF0dmQnAL8D_FuNg2WxF7uJSYo",
        "y": "orKbmG6L6kRugAB2OWzWNgulXRfyOR06GTm353Er--c",
        "d": "YobJpI7p7T5dfU0cDRE4SQwp0eOFR6LOGrsqZE1GG1A"
    }"##;

    /// Test for generating keys
    #[test]
    fn test_generate_key() {
        
        let result = generate_key();
        // println!("{:?}", result);

        // Check for the expected elliptic curve (used by ION to generate keys).
        match result.params {
            Params::EC(ecparams) => assert_eq!(ecparams.curve, Some(String::from("secp256k1"))),
            _ => panic!()
        }
    }

    #[test]
    fn test_generate_keys() {
        
        let result = generate_keys();
        assert_eq!(result.len(), 3);
        assert!(result.contains_key(&KeyType::UpdateKey));
        assert!(result.contains_key(&KeyType::RecoveryKey));
        assert!(result.contains_key(&KeyType::SigningKey));
    }
}
