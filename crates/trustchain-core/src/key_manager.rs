//! Key management API with default implementations.
use crate::{JSON_FILE_EXTENSION, TRUSTCHAIN_DATA};
use serde_json::{from_str, to_string_pretty as to_json};
use ssi::jwk::JWK;
use ssi::one_or_many::OneOrMany;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;

/// An error relating to Trustchain key management.
#[derive(Error, Debug)]
pub enum KeyManagerError {
    /// Key does not exist.
    #[error("Key does not exist.")]
    FailedToLoadKey,
    /// Key could not be saved.
    #[error("Key could not be saved.")]
    FailedToSaveKey,
    /// Failed to read UTF-8 data.
    #[error("Failed to read UTF-8 data.")]
    FailedToReadUTF8,
    /// Failed to parse JSON string to JWK.
    #[error("Failed to parse JSON string to JWK.")]
    FailedToParseJWK,
    /// Failed to create path for DID keys during save.
    #[error("Failed to create path for DID keys during save.")]
    FailedToCreateDir,
    /// Failed to remove key.
    #[error("Failed to remove key.")]
    FailedToRemoveKey,
    /// No TRUSTCHAIN_DATA environment variable.
    #[error("No TRUSTCHAIN_DATA environment variable.")]
    TrustchainDataNotPresent,
    /// Expected only one key but found many.
    #[error("Expected only one key but found many.")]
    InvalidManyKeys,
    /// Wrapped SSI JWK error.
    #[error(transparent)]
    SSIJWKError(#[from] ssi::jwk::Error),
}

/// KeyType enum.
#[derive(Debug, PartialEq, Eq, Hash)]
pub enum KeyType {
    UpdateKey,
    NextUpdateKey,
    RecoveryKey,
    SigningKey,
}

pub trait ControllerKeyManager: KeyManager {
    /// Reads a recovery key.
    fn read_recovery_key(&self, did_suffix: &str) -> Result<JWK, KeyManagerError> {
        let key = self.read_key(did_suffix, &KeyType::RecoveryKey);
        self.only_one_key(key)
    }
    /// Reads an update key.
    fn read_update_key(&self, did_suffix: &str) -> Result<JWK, KeyManagerError> {
        let key = self.read_key(did_suffix, &KeyType::UpdateKey);
        self.only_one_key(key)
    }

    /// Reads a candidate next update key.
    fn read_next_update_key(&self, did_suffix: &str) -> Result<JWK, KeyManagerError> {
        let key = self.read_key(did_suffix, &KeyType::NextUpdateKey);
        self.only_one_key(key)
    }

    /// Apply the `next_update_key` to `update_key` and remove next_update_key
    fn apply_next_update_key(
        &self,
        did_suffix: &str,
        next_update_key: &JWK,
    ) -> Result<(), KeyManagerError> {
        // Save as update key
        self.save_key(did_suffix, KeyType::UpdateKey, next_update_key, true)?;

        // Remove "next_update_key"
        self.remove_keys(did_suffix, &KeyType::NextUpdateKey)?;

        Ok(())
    }
}

pub trait AttestorKeyManager: KeyManager {
    /// Reads one or more signing keys.
    fn read_signing_keys(&self, did_suffix: &str) -> Result<OneOrMany<JWK>, KeyManagerError> {
        self.read_key(did_suffix, &KeyType::SigningKey)
    }
}

pub trait KeyManager {
    /// Reads a key of a given type.
    fn read_key(
        &self,
        did_suffix: &str,
        key_type: &KeyType,
    ) -> Result<OneOrMany<JWK>, KeyManagerError> {
        // Make path
        let path = &self.get_path(did_suffix, key_type, false)?;

        // Open the file
        let file = File::open(path);

        // Read from the file and return
        if let Ok(file) = file {
            self.read_keys_from(Box::new(file))
        } else {
            Err(KeyManagerError::FailedToLoadKey)
        }
    }

    /// Check only one key is present and return key.
    fn only_one_key(
        &self,
        key: Result<OneOrMany<JWK>, KeyManagerError>,
    ) -> Result<JWK, KeyManagerError> {
        match key {
            Ok(OneOrMany::One(x)) => Ok(x),
            Ok(OneOrMany::Many(_)) => Err(KeyManagerError::InvalidManyKeys),
            Err(e) => Err(e),
        }
    }

    /// Reads one key from a Reader.
    fn read_keys_from(&self, mut reader: Box<dyn Read>) -> Result<OneOrMany<JWK>, KeyManagerError> {
        // Read a UTF-8 string from the reader.
        let buf: &mut String = &mut String::new();
        let read_result = reader.read_to_string(buf);

        // Read the string as a serialized JWK instance.
        let jwk_result = match read_result {
            Ok(_) => from_str::<OneOrMany<JWK>>(buf),
            Err(_) => return Err(KeyManagerError::FailedToReadUTF8),
        };

        // Return the JWK.
        match jwk_result {
            Ok(x) => Ok(x),
            Err(_) => Err(KeyManagerError::FailedToParseJWK),
        }
    }

    /// Gets path for a given DID and key type
    fn get_path(
        &self,
        did_suffix: &str,
        key_type: &KeyType,
        dir_only: bool,
    ) -> Result<PathBuf, KeyManagerError> {
        // Get the stem for the corresponding key type
        let file_name = match key_type {
            KeyType::UpdateKey => format!("update_key{}", JSON_FILE_EXTENSION),
            KeyType::NextUpdateKey => format!("next_update_key{}", JSON_FILE_EXTENSION),
            KeyType::RecoveryKey => format!("recovery_key{}", JSON_FILE_EXTENSION),
            KeyType::SigningKey => format!("signing_key{}", JSON_FILE_EXTENSION),
        };

        // Get environment for TRUSTCHAIN_DATA
        let path: String = match std::env::var(TRUSTCHAIN_DATA) {
            Ok(val) => val,
            Err(_) => return Err(KeyManagerError::TrustchainDataNotPresent),
        };

        // Makre directory name
        let directory = Path::new(path.as_str())
            .join("key_manager")
            .join(did_suffix);

        // Make a path
        if dir_only {
            Ok(directory)
        } else {
            Ok(directory.join(file_name))
        }
    }

    /// Checks whether keys already exist on disk.
    fn keys_exist(&self, did_suffix: &str, key_type: &KeyType) -> bool {
        self.get_path(did_suffix, key_type, false).unwrap().exists()
    }

    /// Saves a key to disk.
    fn save_key(
        &self,
        did_suffix: &str,
        key_type: KeyType,
        key: &JWK,
        overwrite: bool,
    ) -> Result<(), KeyManagerError> {
        self.save_keys(
            did_suffix,
            key_type,
            &OneOrMany::One(key.clone()),
            overwrite,
        )
    }

    /// Saves one or more keys to disk.
    fn save_keys(
        &self,
        did_suffix: &str,
        key_type: KeyType,
        keys: &OneOrMany<JWK>,
        overwrite: bool,
    ) -> Result<(), KeyManagerError> {
        // Get directory and path
        let directory = &self.get_path(did_suffix, &key_type, true)?;
        let path = &self.get_path(did_suffix, &key_type, false)?;

        // Stop if keys already exist and overwrite is false.
        if self.keys_exist(did_suffix, &key_type) && !overwrite {
            return Err(KeyManagerError::FailedToSaveKey);
        }

        // Make directory if non-existent
        match std::fs::create_dir_all(directory) {
            Ok(_) => (),
            Err(_) => return Err(KeyManagerError::FailedToCreateDir),
        };

        // Open the new file
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path);

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

    /// Removes file from disk for `key_type` of `did_suffix`.
    fn remove_keys(&self, did_suffix: &str, key_type: &KeyType) -> Result<(), KeyManagerError> {
        // Make path
        let path = &self.get_path(did_suffix, key_type, false)?;

        // Check path exists as a file
        if path.is_file() {
            match std::fs::remove_file(path) {
                Ok(_) => Ok(()),
                Err(_) => Err(KeyManagerError::FailedToRemoveKey),
            }
        } else {
            Err(KeyManagerError::FailedToRemoveKey)
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::data::{
        TEST_NEXT_UPDATE_KEY, TEST_RECOVERY_KEY, TEST_SIGNING_KEYS, TEST_UPDATE_KEY,
    };
    use crate::utils::generate_key;
    use mockall::mock;
    use ssi::jwk::Params;
    use std::io::Read;
    use std::sync::Once;

    pub struct TestKeyManager;

    impl KeyManager for TestKeyManager {}
    impl AttestorKeyManager for TestKeyManager {}
    impl ControllerKeyManager for TestKeyManager {}

    /// Set-up tempdir and use as env var for `TRUSTCHAIN_DATA`.
    // https://stackoverflow.com/questions/58006033/how-to-run-setup-code-before-any-tests-run-in-rust
    static INIT: Once = Once::new();
    pub fn init() {
        INIT.call_once(|| {
            // initialization code here
            let tempdir = tempfile::tempdir().unwrap();
            std::env::set_var(TRUSTCHAIN_DATA, Path::new(tempdir.as_ref().as_os_str()));
            // Manually drop here so additional writes in the init call are not removed
            drop(tempdir);
        });
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
        // Make path for this test
        let did_suffix = "test_read_update_key";

        // Save key to temp file
        let expected_key: JWK = serde_json::from_str(TEST_UPDATE_KEY).unwrap();

        let target = TestKeyManager;
        target.save_key(did_suffix, KeyType::UpdateKey, &expected_key, true)?;

        // Read key from file
        let res = target.read_update_key(did_suffix);

        // Assert read is ok
        assert!(res.is_ok());

        // Assert same key is read back
        assert_eq!(expected_key, res.unwrap());

        Ok(())
    }

    #[test]
    fn test_read_recovery_key() -> Result<(), Box<dyn std::error::Error>> {
        // Make path for this test
        let did_suffix = "test_read_recovery_key";

        // Save key to temp file
        let expected_key: JWK = serde_json::from_str(TEST_RECOVERY_KEY)?;

        let target = TestKeyManager;
        target.save_key(did_suffix, KeyType::RecoveryKey, &expected_key, true)?;

        // Read key from file
        let res = target.read_recovery_key(did_suffix);

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

        let target = TestKeyManager;
        let result = target.read_keys_from(Box::new(mock_reader));
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
    fn test_keys_exist() -> Result<(), Box<dyn std::error::Error>> {
        init();

        let target = TestKeyManager;

        // Make keys
        let expected_key: JWK = serde_json::from_str(TEST_UPDATE_KEY)?;

        // Make path for this test
        let did_suffix = "test_keys_exist";

        assert!(!target.keys_exist(did_suffix, &KeyType::UpdateKey));

        // Save to temp
        target.save_key(did_suffix, KeyType::UpdateKey, &expected_key, true)?;

        assert!(target.keys_exist(did_suffix, &KeyType::UpdateKey));

        // Failing overwrite
        let try_overwrite = target.save_key(did_suffix, KeyType::UpdateKey, &expected_key, false);
        assert!(try_overwrite.is_err());

        // Successful overwrite
        let try_overwrite = target.save_key(did_suffix, KeyType::UpdateKey, &expected_key, true);
        assert!(try_overwrite.is_ok());

        Ok(())
    }

    #[test]
    fn test_save_key() -> Result<(), Box<dyn std::error::Error>> {
        // Make path for this test
        let did_suffix = "test_save_key";

        // Make keys
        let expected_key: JWK = serde_json::from_str(TEST_UPDATE_KEY)?;

        // Save to temp
        let target = TestKeyManager;
        target.save_key(did_suffix, KeyType::UpdateKey, &expected_key, true)?;

        // Read keys
        let actual_key = target.read_update_key(did_suffix)?;

        // Check keys saved are same as those read back
        assert_eq!(expected_key, actual_key);

        Ok(())
    }

    #[test]
    fn test_save_keys() -> Result<(), Box<dyn std::error::Error>> {
        // Make path for this test
        let did_suffix = "test_save_keys";

        // Make keys
        let keys: OneOrMany<JWK> = serde_json::from_str(TEST_SIGNING_KEYS)?;

        // Save to temp
        let target = TestKeyManager;
        target.save_keys(did_suffix, KeyType::SigningKey, &keys, true)?;

        // Read keys
        let actual_signing = target.read_signing_keys(did_suffix)?;

        // Check keys saved are same as those read back
        assert_eq!(keys, actual_signing);

        Ok(())
    }

    #[test]
    fn test_apply_next_update_key() -> Result<(), Box<dyn std::error::Error>> {
        init();

        // Make path for this test
        let did_suffix = "test_apply_next_update_key";

        let target = TestKeyManager;

        // Save update key and next update key
        let update_key: JWK = serde_json::from_str(TEST_UPDATE_KEY)?;
        let next_update_key: JWK = serde_json::from_str(TEST_NEXT_UPDATE_KEY)?;
        target.save_key(did_suffix, KeyType::UpdateKey, &update_key, true)?;
        target.save_key(did_suffix, KeyType::NextUpdateKey, &next_update_key, true)?;

        // Read next update
        let loaded_update_key = target.read_update_key(did_suffix)?;
        let loaded_next_update_key = target.read_next_update_key(did_suffix)?;
        assert_eq!(loaded_update_key, update_key);
        assert_eq!(loaded_next_update_key, next_update_key);

        // // Apply next update key
        target.apply_next_update_key(did_suffix, &next_update_key)?;

        // // Check if next_update_key is removed
        let path = target.get_path(did_suffix, &KeyType::NextUpdateKey, false)?;
        if path.is_file() {
            return Err(Box::new(KeyManagerError::FailedToRemoveKey));
        }

        // Check the update key is now next_update_key
        let actual_update_key = target.read_update_key(did_suffix)?;

        // Check update key is now next_update_key
        assert_eq!(next_update_key, actual_update_key);

        Ok(())
    }
}
