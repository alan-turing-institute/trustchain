use serde_json::{from_str, to_string_pretty as to_json};
use ssi::jwk::{Params, JWK};
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
    #[error("Failed to create path for DID keys during save.")]
    FailedToCreateDir,
    #[error("No Trustchain data environment variable.")]
    TrustchainDataNotPresent,
    #[error("Many keys when should be one.")]
    InvalidManyKeys,
}

/// KeyType enum.
#[derive(Debug, PartialEq, Eq, Hash)]
pub enum KeyType {
    UpdateKey,
    NextUpdateKey,
    RecoveryKey,
    SigningKey,
}

/// Generates a new cryptographic key.
pub fn generate_key() -> JWK {
    JWK::generate_secp256k1().expect("Could not generate key.")
}

/// Generates a set of update, recovery and signing keys.
// TODO: consider droppping this function as creating keys is easier one by one.
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
pub fn read_key(did: &str, key_type: KeyType) -> Result<OneOrMany<JWK>, KeyManagerError> {
    // Get the stem for the corresponding key type
    let stem_name = match key_type {
        KeyType::UpdateKey => "update_key.json",
        KeyType::NextUpdateKey => "next_update_key.json",
        KeyType::RecoveryKey => "recovery_key.json",
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
        read_keys_from(Box::new(file))
    } else {
        Err(KeyManagerError::FailedToLoadKey)
    }
}

/// Check only one key is present and return key.
fn only_one_key(key: Result<OneOrMany<JWK>, KeyManagerError>) -> Result<JWK, KeyManagerError> {
    match key {
        Ok(OneOrMany::One(x)) => Ok(x),
        Ok(OneOrMany::Many(_)) => Err(KeyManagerError::InvalidManyKeys),
        Err(e) => Err(e),
    }
}

/// Reads an update key.
pub fn read_update_key(did: &str) -> Result<JWK, KeyManagerError> {
    let key = read_key(did, KeyType::UpdateKey);
    only_one_key(key)
}

/// Reads a recovery key.
pub fn read_recovery_key(did: &str) -> Result<JWK, KeyManagerError> {
    let key = read_key(did, KeyType::RecoveryKey);
    only_one_key(key)
}

/// Reads one or more signing keys.
pub fn read_signing_keys(did: &str) -> Result<OneOrMany<JWK>, KeyManagerError> {
    read_key(did, KeyType::SigningKey)
}

/// Reads one key from a Reader.
fn read_keys_from(mut reader: Box<dyn Read>) -> Result<OneOrMany<JWK>, KeyManagerError> {
    // Read a UTF-8 string from the reader.
    let buf: &mut String = &mut String::new();
    let read_result = reader.read_to_string(buf);

    // Read the string as a serialised JWK instance.
    let jwk_result = match read_result {
        Ok(_) => from_str::<OneOrMany<JWK>>(buf),
        Err(_) => return Err(KeyManagerError::FailedToReadUTF8),
    };

    // Return the JWK.
    match jwk_result {
        Ok(x) => return Ok(x),
        Err(_) => return Err(KeyManagerError::FailedToParseJWK),
    };
}

/// Apply the `next_update_key` to `update_key` and remove next_update_key
fn apply_next_update_key() {
    todo!()
}

/// Saves a key to disk.
pub fn save_key(did: &str, key_type: KeyType, key: &JWK) -> Result<(), KeyManagerError> {
    save_keys(did, key_type, &OneOrMany::One(key.clone()))
}

/// Saves one or more keys to disk.
pub fn save_keys(
    did: &str,
    key_type: KeyType,
    keys: &OneOrMany<JWK>,
) -> Result<(), KeyManagerError> {
    // Get the stem for the corresponding key type
    let stem_name = match key_type {
        KeyType::UpdateKey => "update_key.json",
        KeyType::NextUpdateKey => "next_update_key.json",
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
    match std::fs::create_dir_all(&path) {
        Ok(_) => (),
        Err(_) => return Err(KeyManagerError::FailedToCreateDir),
    };

    // Open the new file
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path.join(stem_name));

    // Write key to file
    if let Ok(mut file) = file {
        match writeln!(file, "{}", &to_json(keys).unwrap()) {
            Ok(_) => Ok(()),
            Err(_) => Err(KeyManagerError::FailedToSaveKey),
        }
    } else {
        Err(KeyManagerError::FailedToSaveKey)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockall::mock;
    use std::io::Read;
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

    // Print TRUSTCHAIN_DATA dir
    fn print_env() {
        if let Ok(dir) = std::env::var(TRUSTCHAIN_DATA) {
            println!("{}", dir);
        }
    }

    const TEST_SIGNING_KEYS: &str = r##"[
        {
            "kty": "EC",
            "crv": "secp256k1",
            "x": "aPNNzj64rnImzI60EP0iln_u5fyHZ1k47diqmlUrwXw",
            "y": "fbfKhw08ZtGy9vbyJo6kiFohhGFIrnzZIUNDvEQeAYQ",
            "d": "sfsIThyN_6EKPjhQasF8yR27-qlQPUTGiP4QtkPTKM8"
        },
        {
            "kty": "EC",
            "crv": "secp256k1",
            "x": "gjk_d4WRM5hFD7tP8vvXhHgp0MQkKwFX0uAvyjNJQJg",
            "y": "e5lq0RW41Y5MH1pOTm-3_18GcxKp1lO4SfbzApRaVtE",
            "d": "U7pUq3BovVnYT1mi1lds60wbueUKb5GobV_WvjOuY14"
        }
    ]
    "##;

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
    fn test_read_update_key() -> Result<(), Box<dyn std::error::Error>> {
        // Init env
        init();

        // Make path for this test
        let did_path_str = "test_read_update_key";

        // Save key to temp file
        let expected_key: JWK = serde_json::from_str(TEST_UPDATE_KEY).unwrap();
        save_key(did_path_str, KeyType::UpdateKey, &expected_key)?;

        // Read key from file
        let res = read_update_key(did_path_str);

        // Assert read is ok
        assert!(res.is_ok());

        // Assert same key is read back
        assert_eq!(expected_key, res.unwrap());

        Ok(())
    }

    #[test]
    fn test_read_recovery_key() -> Result<(), Box<dyn std::error::Error>> {
        // Init env
        init();

        // Make path for this test
        let did_path_str = "test_read_recovery_key";

        // Save key to temp file
        let expected_key: JWK = serde_json::from_str(TEST_RECOVERY_KEY)?;
        save_key(did_path_str, KeyType::RecoveryKey, &expected_key)?;

        // Read key from file
        let res = read_recovery_key(did_path_str);

        // Assert read is ok
        assert!(res.is_ok());

        // Assert same key is read back
        assert_eq!(expected_key, res.unwrap());

        Ok(())
    }

    #[test]
    fn test_read_keys_from() {
        // Construct a mock Reader.
        let mut mock_reader = MockReader::new();
        mock_reader.expect_read_to_string().return_once(move |buf| {
            // Implement the side effect of filling the buffer.
            buf.push_str(TEST_UPDATE_KEY);
            // Dummy return value
            std::io::Result::Ok(0)
        });

        let result = read_keys_from(Box::new(mock_reader));
        assert!(result.is_ok());

        let key = result.unwrap();

        // Check for the expected elliptic curve.
        if let OneOrMany::One(key) = key {
            match &key.params {
                Params::EC(ecparams) => assert_eq!(ecparams.curve, Some(String::from("secp256k1"))),
                _ => panic!(),
            }
        } else {
            panic!()
        }
    }

    #[test]
    fn test_save_key() -> Result<(), Box<dyn std::error::Error>> {
        // Set env var
        init();

        // Make path for this test
        let did_path_str = "test_save_key";

        // Make keys
        let expected_key: JWK = serde_json::from_str(TEST_UPDATE_KEY)?;

        // Save to temp
        save_key(did_path_str, KeyType::UpdateKey, &expected_key)?;

        // Read keys
        let actual_key = read_update_key(did_path_str)?;

        // Check keys saved are same as those read back
        assert_eq!(expected_key, actual_key);

        Ok(())
    }

    #[test]
    fn test_save_keys() -> Result<(), Box<dyn std::error::Error>> {
        // Set env var
        init();

        // Make path for this test
        let did_path_str = "test_save_keys";

        // Make keys
        let keys: OneOrMany<JWK> = serde_json::from_str(TEST_SIGNING_KEYS)?;

        // Save to temp
        save_keys(did_path_str, KeyType::SigningKey, &keys)?;

        // Read keys
        let actual_signing = read_signing_keys(did_path_str)?;

        // Check keys saved are same as those read back
        assert_eq!(keys, actual_signing);

        Ok(())
    }

    #[test]
    fn test_apply_next_update_key() -> Result<(), Box<dyn std::error::Error>> {
        // Set env var
        init();

        // Make path for this test
        let did_path_str = "test_apply_next_update_key";

        todo!();
        Ok(())
    }
}
