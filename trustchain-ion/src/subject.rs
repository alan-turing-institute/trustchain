use ssi::{jwk::JWK, one_or_many::OneOrMany};
use trustchain_core::{
    key_manager::{KeyManager, KeyManagerError, SubjectKeyManager},
    subject::Subject,
};

pub struct IONSubject {
    did: String,
    signing_keys: Option<OneOrMany<JWK>>,
}

impl SubjectKeyManager for IONSubject {}

impl KeyManager for IONSubject {}

impl IONSubject {
    /// Construct a new TrustchainSubject instance.
    pub fn new(did: &str) -> Self {
        Self {
            did: did.to_owned(),
            signing_keys: None,
        }
    }

    fn load(&mut self, did: &str) -> Result<(), KeyManagerError> {
        if let Ok(signing_keys) = self.read_signing_keys(did) {
            self.signing_keys = Some(signing_keys);
            Ok(())
        } else {
            Err(KeyManagerError::FailedToLoadKey)
        }
    }
}

type SubjectData = (String, OneOrMany<JWK>);

impl From<SubjectData> for IONSubject {
    fn from(subject_data: SubjectData) -> Self {
        IONSubject {
            did: subject_data.0,
            signing_keys: Some(subject_data.1),
        }
    }
}

impl Subject for IONSubject {
    fn did(&self) -> &str {
        &self.did
    }

    // /// Gets the public part of a signing key.
    // fn get_public_key(&self, key_id: Option<String>) -> Result<JWK, KeyManagerError> {
    //     // let keys = read_keys(&self.did);
    //     // let keys = match keys {
    //     //     Ok(map) => map,
    //     //     Err(e) => return Err(e)
    //     // };
    //     // let signing = keys.get(&KeyType::SigningKey);
    //     todo!();
    // }

    // fn signing_keys(&self) -> OneOrMany<JWK> {
    //     todo!()
    // }

    // fn generate_signing_keys(&self) -> OneOrMany<JWK> {
    //     todo!()
    // }

    // fn save(&self) -> Result<(), SubjectError> {
    //     todo!()
    // }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::from_str;
    use ssi::did::Document;

    use trustchain_core::data::TEST_SIGNING_KEYS;

    // // Set-up tempdir and use as env var for TRUSTCHAIN_DATA
    // // https://stackoverflow.com/questions/58006033/how-to-run-setup-code-before-any-tests-run-in-rust
    // static INIT: Once = Once::new();
    // pub fn init() {
    //     INIT.call_once(|| {
    //         // initialization code here
    //         let tempdir = tempfile::tempdir().unwrap();
    //         std::env::set_var(TRUSTCHAIN_DATA, Path::new(tempdir.as_ref().as_os_str()));
    //     });
    // }

    #[test]
    fn test_from() -> Result<(), Box<dyn std::error::Error>> {
        let did = "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9YP";
        let keys: OneOrMany<JWK> = serde_json::from_str(TEST_SIGNING_KEYS)?;

        let target = IONSubject::from((did.to_string(), keys.clone()));

        assert_eq!(target.did(), did);
        assert_eq!(target.signing_keys.unwrap(), keys);

        Ok(())
    }

    // #[test]
    // fn test_attest() -> Result<(), Box<dyn std::error::Error>> {
    //     let did = "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9YP";

    //     // Construct a mock KeyManager.
    //     let mut key_manager = KeyManager::default();

    //     // let keys: OneOrMany<JWK> = serde_json::from_str(TEST_SIGNING_KEYS)?;

    //     key_manager.expect_read_signing_keys().return_once(|did| {
    //         let keys: OneOrMany<JWK> = serde_json::from_str(TEST_SIGNING_KEYS).unwrap();
    //         Result::Ok(keys)
    //     });

    //     // TEMP TEST:
    //     // let keys = key_manager.read_signing_keys(did);
    //     // println!("hello!");
    //     // println!("{:?}", keys);
    //     // assert!(keys.is_ok());

    //     let target = TrustchainSubject::new(did, key_manager);

    //     let doc = Document::from_json(TEST_TRUSTCHAIN_DOCUMENT).expect("Document failed to load.");
    //     let result = target.attest(&doc, Option::None);

    //     assert!(result.is_ok());
    //     // let proof_result = result.unwrap();

    //     // // Test that the proof_result string is valid JSON.
    //     // // TODO: figure out the correct result type here (guessed &str).
    //     // let json_proof_result: Result<&str, serde_json::Error> = serde_json::from_str(&proof_result);

    //     // TODO: check for a key-value in the JSON.
    //     Ok(())
    // }

    // #[test]
    // fn test_signing_keys() {}

    // #[test]
    // fn test_load() {}

    // #[test]
    // fn test_save() {}

    // #[test]
    // fn test_get_public_key() {}

    // #[test]
    // fn test_generate_signing_keys() {}
}
