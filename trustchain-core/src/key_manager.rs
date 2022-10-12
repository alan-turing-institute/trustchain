use serde_json::{from_str, to_string_pretty as to_json};
use ssi::jwk::{Base64urlUInt, ECParams, Params, JWK};
use ssi::one_or_many::OneOrMany;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use thiserror::Error;

use crate::TRUSTCHAIN_DATA;

/// An error relating to Trustchain key management.
#[derive(Error, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum KeyManagerError {
    #[error("Key does not exist.")]
    FailedToLoadKey,
    #[error("Key could not be saved.")]
    FailedToSaveKey,
    #[error("Failed to read UTF-8 data.")]
    FailedToReadUTF8,
    #[error("Failed to parse JSON string to JWK.")]
    FailedToParseJWK,
    #[error("No Trustchain data environment variable.")]
    TrustchainDataNotPresent,
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
    JWK::generate_secp256k1().expect("Could not generate key.")
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

/// Reads a key of a given type.
pub fn read_key(did: &str, key_type: KeyType) -> Result<JWK, KeyManagerError> {
    // Get the stem for the corresponding key type
    let stem_name = match key_type {
        KeyType::UpdateKey => "update_key.json",
        KeyType::RecoveryKey => "recovery_key.json",
        // TODO: this probably read OneOrMany keys from a single file
        //       see `fn read_keys_from()`
        KeyType::SigningKey => "signing_key.json",
    };

    // Get environment for TRUSTCHAIN_DATA
    let path: String = match std::env::var(TRUSTCHAIN_DATA) {
        Ok(val) => val,
        Err(_) => return Err(KeyManagerError::TrustchainDataNotPresent),
    };

    // Open the file
    let file = File::open(
        Path::new(path.as_str())
            .join("key_manager")
            .join(did)
            .join(stem_name),
    );

    // Read from the file and return
    if let Ok(file) = file {
        read_key_from(Box::new(file))
    } else {
        Err(KeyManagerError::FailedToLoadKey)
    }
}

/// Reads an update key.
pub fn read_update_key(did: &str) -> Result<JWK, KeyManagerError> {
    read_key(did, KeyType::UpdateKey)
}

/// Reads a recovery key.
pub fn read_recovery_key(did: &str) -> Result<JWK, KeyManagerError> {
    read_key(did, KeyType::RecoveryKey)
}

/// Reads one or more signing keys.
pub fn read_signing_keys(did: &str) -> Result<OneOrMany<JWK>, KeyManagerError> {
    todo!()
}

/// Reads one key from a Reader.
fn read_key_from(mut reader: Box<dyn Read>) -> Result<JWK, KeyManagerError> {
    // Read a UTF-8 string from the reader.
    let buf: &mut String = &mut String::new();
    let read_result = reader.read_to_string(buf);

    // Read the string as a serialised JWK instance.
    let jwk_result = match read_result {
        Ok(_) => from_str::<JWK>(buf),
        Err(_) => return Err(KeyManagerError::FailedToReadUTF8),
    };

    // Return the JWK.
    match jwk_result {
        Ok(x) => return Ok(x),
        Err(_) => return Err(KeyManagerError::FailedToParseJWK),
    };
}

/// Reads one or more keys from a Reader.
fn read_keys_from(mut reader: Box<dyn Read>) -> Result<OneOrMany<JWK>, KeyManagerError> {
    // TODO: Use the Deserialize trait on OneOrMany<JWK>
    // see: https://demo.didkit.dev/2021/11/29/ssi-aleo-rustdoc/ssi/one_or_many/enum.OneOrMany.html#trait-implementations
    todo!()
}

/// Saves a key to disk.
pub fn save_key(did: &str, key_type: KeyType, key: &JWK) -> Result<(), KeyManagerError> {
    // Get the stem for the corresponding key type
    let stem_name = match key_type {
        KeyType::UpdateKey => "update_key.json",
        KeyType::RecoveryKey => "recovery_key.json",
        KeyType::SigningKey => "signing_key.json",
    };

    // Get environment for TRUSTCHAIN_DATA
    let path: String = match std::env::var(TRUSTCHAIN_DATA) {
        Ok(val) => val,
        Err(_) => return Err(KeyManagerError::TrustchainDataNotPresent),
    };

    // Make a path
    let path = Path::new(path.as_str()).join("key_manager").join(did);

    // Make directory if non-existent
    // TODO: handle error
    std::fs::create_dir_all(&path).unwrap();

    // Open the new file
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path.join(stem_name));

    // Write key to file
    if let Ok(mut file) = file {
        match writeln!(file, "{}", &to_json(key).unwrap()) {
            Ok(_) => Ok(()),
            Err(_) => Err(KeyManagerError::FailedToSaveKey),
        }
    } else {
        Err(KeyManagerError::FailedToSaveKey)
    }
}

/// Saves one or more keys to disk.
pub fn save_keys(did: &str, key_type: KeyType, keys: &OneOrMany<JWK>) -> () {
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
    use mockall::mock;
    use std::io::Read;
    // use did_ion::sidetree::Sidetree;
    // use serde_json::to_string_pretty as to_json;

    use super::*;

    fn init() {
        std::env::set_var(
            TRUSTCHAIN_DATA,
            Path::new(std::env::var("CARGO_WORKSPACE_DIR").unwrap().as_str())
                .join("resources/test/"),
        );
        println!("{:?}", std::env::var(TRUSTCHAIN_DATA));
    }

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
            _ => panic!(),
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

    // Mock the std::io::Read trait.
    mock! {
        Reader {}     // Name of the mock struct, less the "Mock" prefix
        impl Read for Reader {   // specification of the trait to mock
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize>;
            fn read_to_string(&mut self, buf: &mut String) -> std::io::Result<usize>;
        }
    }

    #[test]
    fn test_read_update_key() {
        // Init env variables
        init();

        // Read key from file
        let res = read_update_key("test_did");
        assert!(res.is_ok());

        // Check is the same key as here
        let expected_key: JWK = serde_json::from_str(TEST_UPDATE_KEY).unwrap();
        let actual_key = res.unwrap();
        assert_eq!(expected_key, actual_key);
    }

    #[test]
    fn test_read_recovery_key() {
        // Init env variables
        init();

        // Read key from file
        let res = read_recovery_key("test_did");
        assert!(res.is_ok());

        // Check is the same key as here
        let expected_key: JWK = serde_json::from_str(TEST_RECOVERY_KEY).unwrap();
        let actual_key = res.unwrap();
        assert_eq!(expected_key, actual_key);
    }

    #[test]
    fn test_read_key_from() {
        // Construct a mock Reader.
        let mut mock_reader = MockReader::new();
        mock_reader.expect_read_to_string().return_once(move |buf| {
            // Implement the side effect of filling the buffer.
            buf.push_str(TEST_UPDATE_KEY);
            // Dummy return value
            std::io::Result::Ok(0)
        });

        // Construct an empty buffer.
        let buf: &mut String = &mut String::new();
        // mock_reader.read_to_string(buf);
        // println!("{}", buf);
        let result = read_key_from(Box::new(mock_reader));
        assert!(result.is_ok());
        let key = result.unwrap();

        // Check for the expected elliptic curve (used by ION to generate keys).
        match &key.params {
            Params::EC(ecparams) => assert_eq!(ecparams.curve, Some(String::from("secp256k1"))),
            _ => panic!(),
        }
    }

    #[test]
    fn test_save_key() {
        // TODO: write test to save a given key to file
        // Init env variables
        init();

        todo!()
    }
}
