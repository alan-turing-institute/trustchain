use std::convert::TryFrom;

use did_ion::sidetree::Sidetree;
use did_ion::ION;
use ssi::did::Document;
use ssi::{jwk::JWK, one_or_many::OneOrMany};
use trustchain_core::key_manager::KeyType;
use trustchain_core::{
    attestor::{Attestor, AttestorError},
    key_manager::{AttestorKeyManager, KeyManager, KeyManagerError},
    Subject,
};

pub struct IONAttestor {
    did: String,
}

impl AttestorKeyManager for IONAttestor {}

impl KeyManager for IONAttestor {}

impl IONAttestor {
    /// Construct a new TrustchainSubject instance.
    pub fn new(did: &str) -> Self {
        Self {
            did: did.to_owned(),
        }
    }

    fn signing_keys(&self) -> Result<OneOrMany<JWK>, KeyManagerError> {
        self.read_signing_keys(&self.did)
    }

    /// Get the Subject's signing key.
    fn signing_key(&self, key_id: Option<&str>) -> Result<JWK, KeyManagerError> {
        // let keys = self.read_signing_keys(&self.did)?;
        let keys = self.signing_keys()?;
        // If no key_id is given, return the first available key.
        if key_id.is_none() {
            match keys.first() {
                Some(key) => return Ok(key.to_owned()),
                None => Err(KeyManagerError::FailedToLoadKey),
            }
        } else {
            let key_id = key_id.unwrap();
            // Iterate over the available keys.
            for key in keys.into_iter() {
                // If the key has a key_id which matches the given key_id, return it.
                // Otherwise continue.
                match key.key_id {
                    Some(ref this_key_id) => {
                        if this_key_id == key_id {
                            return Ok(key);
                        }
                    }
                    None => continue,
                }
            }
            // If none of the keys has a matching key_id, the required key does not exist.
            Err(KeyManagerError::FailedToLoadKey)
        }
    }
}

type AttestorData = (String, OneOrMany<JWK>);

impl TryFrom<AttestorData> for IONAttestor {
    type Error = Box<dyn std::error::Error>;

    fn try_from(data: AttestorData) -> Result<Self, Self::Error> {
        let subject = IONAttestor { did: data.0 };

        // Attempt to save the keys but do not overwrite existing key information.
        subject.save_keys(&subject.did, KeyType::SigningKey, &data.1, false)?;
        Ok(subject)
    }
}

impl Subject for IONAttestor {
    fn did(&self) -> &str {
        &self.did
    }
}

impl Attestor for IONAttestor {
    fn attest(&self, doc: &Document, key_id: Option<&str>) -> Result<String, AttestorError> {
        let algorithm = ION::SIGNATURE_ALGORITHM;

        let canonical_document = match ION::json_canonicalization_scheme(&doc) {
            Ok(str) => str,
            Err(_) => return Err(AttestorError::InvalidDocumentParameters(doc.id.clone())),
        };
        let proof = (&doc.id.clone(), canonical_document);

        let proof_json = match ION::json_canonicalization_scheme(&proof) {
            Ok(str) => str,
            Err(_) => return Err(AttestorError::InvalidDocumentParameters(doc.id.clone())),
        };

        let proof_json_bytes = ION::hash(proof_json.as_bytes());

        // Get the signing key.
        let signing_key = match self.signing_key(key_id) {
            Ok(key) => key,
            Err(_) => {
                if key_id.is_none() {
                    return Err(AttestorError::NoSigningKey(doc.id.to_string()));
                } else {
                    return Err(AttestorError::NoSigningKeyWithId(
                        doc.id.to_string(),
                        key_id.unwrap().to_string(),
                    ));
                }
            }
        };

        match ssi::jwt::encode_sign(algorithm, &proof_json_bytes, &signing_key) {
            Ok(str) => Ok(str),
            Err(e) => Err(AttestorError::SigningError(doc.id.clone(), e.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssi::did::Document;

    use trustchain_core::data::{TEST_SIGNING_KEYS, TEST_TRUSTCHAIN_DOCUMENT};
    use trustchain_core::init;

    #[test]
    fn test_try_from() -> Result<(), Box<dyn std::error::Error>> {
        init();
        assert_eq!(0, 0);
        let signing_keys: OneOrMany<JWK> = serde_json::from_str(TEST_SIGNING_KEYS)?;
        let did = "did_try_from";

        let target = IONAttestor::try_from((did.to_string(), signing_keys.clone()))?;

        assert_eq!(target.did(), did);

        let loaded_signing_keys = target.signing_keys()?;
        assert_eq!(loaded_signing_keys, signing_keys);

        Ok(())
    }

    #[test]
    fn test_attest() -> Result<(), Box<dyn std::error::Error>> {
        let did = "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9YP";
        let keys: OneOrMany<JWK> = serde_json::from_str(TEST_SIGNING_KEYS)?;
        let signing_key = keys.first().unwrap();

        let target = IONAttestor::try_from((did.to_string(), keys.clone()))?;

        println!("{:?}", target.read_signing_keys(did));

        let doc = Document::from_json(TEST_TRUSTCHAIN_DOCUMENT).expect("Document failed to load.");

        let result = target.attest(&doc, None);
        assert!(result.is_ok());

        let proof_result = result?;

        // Test that the proof_result string is valid JSON.
        // TODO: figure out the correct result type here (guessed &str).
        let json_proof_result: Result<&str, serde_json::Error> =
            serde_json::from_str(&proof_result);

        // TODO: check for a key-value in the JSON.
        // println!("{:?}", json_proof_result);
        Ok(())
    }

    // #[test]
    // fn test_signing_key() {}
}
