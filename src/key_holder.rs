use std::iter::Map;

use did_ion::sidetree::{Sidetree, SidetreeClient};
use did_ion::ION;
use ssi::one_or_many::OneOrMany;
use serde_json::Value;
use ssi::jwk::{Base64urlUInt, ECParams, Params, JWK};
use thiserror::Error;

/// An error relating to Trustchain key management.
#[derive(Error, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum KeyHolderError {
    #[error("Key does not exist.")]
    FailToLoadKey,
}

/// KeyType enum.
pub enum KeyType {
    UpdateKey,
    RecoveryKey,
    SigningKey,
}

/// Trait for common KeyHolder functionality.
trait KeyHolder {
    fn generate_key(&self) -> JWK;
    fn load_update_key(&self, did: &str) -> Result<JWK, KeyHolderError>;
    fn load_recovery_key(&self, did: &str) -> Result<JWK, KeyHolderError>;
    fn load_signing_keys(&self, did: &str) -> Result<OneOrMany<JWK>, KeyHolderError>;
    fn save_key(&self, did: &str, key_type: KeyType, key: &JWK) -> ();
    fn load_keys(&self, did: &str) -> Result<Map<KeyType, OneOrMany<JWK>>, KeyHolderError>;
    fn get_public_key(&self, key_id: Option<String>) -> Result<JWK, KeyHolderError>;
}

/// Struct for common TrustchainKeyHolder.
pub struct TrustchainKeyHolder {
    signing_keys: OneOrMany<JWK>,
    update_key: JWK,
    recovery_key: JWK,
}

impl TrustchainKeyHolder {

    /// Generate a new TrustchainKeyHolder with keys (including a single signing key).
    pub fn new() -> Self {
        let signing_key = ION::generate_key().expect("Could not generate key.");
        let update_key = ION::generate_key().expect("Could not generate key.");
        let recovery_key = ION::generate_key().expect("Could not generate key.");

        Self {
            signing_keys: OneOrMany::One(signing_key),
            update_key,
            recovery_key,
        }
    }

    fn load_keys(&self, did: &str) -> Result<Map<KeyType, OneOrMany<JWK>>, KeyHolderError> {
        todo!()
    }
}

impl KeyHolder for TrustchainKeyHolder {
    fn generate_key(&self) -> JWK {
        todo!()
    }

    fn load_update_key(&self, did: &str) -> Result<JWK, KeyHolderError> {
        todo!()
    }

    fn load_recovery_key(&self, did: &str) -> Result<JWK, KeyHolderError> {
        todo!()
    }

    fn load_signing_keys(&self, did: &str) -> Result<OneOrMany<JWK>, KeyHolderError> {
        todo!()
    }

    fn save_key(&self, did: &str, key_type: KeyType, key: &JWK) -> () {
        todo!()
    }

    fn load_keys(&self, did: &str) -> Result<Map<KeyType, OneOrMany<JWK>>, KeyHolderError> {
        todo!()
    }

    fn get_public_key(&self, key_id: Option<String>) -> Result<JWK, KeyHolderError> {
        todo!()
    }

    // fn load_key(&self) {
    //     // Load previous data
    //     let file_name = format!("update_{}", self.did.as_ref().unwrap());
    //     let ec_read = std::fs::read(file_name).unwrap();
    //     let ec_read = std::str::from_utf8(&ec_read).unwrap();
    //     let ec_params: ECParams = serde_json::from_str(ec_read).unwrap();

    //     // let ec_params = Params::EC(ec_params);
    //     let update_key = JWK::from(Params::EC(ec_params));
    //     println!("Valid key: {}", ION::validate_key(&update_key).is_ok());
    //     // update_key
    //     todo!()
    // }

}

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

    /// Test for loading keys into controller
    #[test]
    fn load_keys() {
        todo!()
    }
}
