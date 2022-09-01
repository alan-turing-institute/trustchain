use did_ion::sidetree::{Sidetree, SidetreeClient};
use did_ion::ION;
use serde_json::Value;
use ssi::jwk::{Base64urlUInt, ECParams, Params, JWK};
use thiserror::Error;

/// An error relating to Trustchain resolution.
#[derive(Error, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ControllerError {
    #[error("Key does not exist.")]
    FailToLoadKey,
}

/// Trait for common Controller functionality.
trait Controller {
    fn generate_key(&self);
    fn load_key(&self);
    fn save_keys(&self);
    fn load_keys(&self);
    fn get_public_key(&self);
}

/// Struct for common TrustchainController.
pub struct TrustchainController {
    signing_key: JWK,
    update_key: JWK,
    recovery_key: JWK,
}

impl TrustchainController {
    /// Generate a new TrustchainController with keys
    pub fn new() -> Self {
        let signing_key = ION::generate_key().expect("Could not generate key.");
        let update_key = ION::generate_key().expect("Could not generate key.");
        let recovery_key = ION::generate_key().expect("Could not generate key.");

        Self {
            signing_key,
            update_key,
            recovery_key,
        }
    }
}

impl TrustchainController {
    fn load_keys() -> () {
        todo!()
    }
    /// Generate a new TrustchainController from keys stored on file.
    pub fn new_from_file(&self, did: &str) -> Result<Self, ControllerError> {
        todo!();
        Ok(Self::new())
    }
}

impl Controller for TrustchainController {
    fn generate_key(&self) {
        todo!();
    }
    fn load_key(&self) {
        todo!();
    }
    fn save_keys(&self) {
        todo!();
    }
    fn load_keys(&self) {
        todo!();
    }
    fn get_public_key(&self) {
        todo!();
    }
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
