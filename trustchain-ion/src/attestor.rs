use did_ion::sidetree::Sidetree;
use did_ion::ION;
use ssi::did::Document;
use ssi::{jwk::JWK, one_or_many::OneOrMany};
use std::convert::TryFrom;
use trustchain_core::key_manager::KeyType;
use trustchain_core::{
    attestor::{Attestor, AttestorError},
    key_manager::{AttestorKeyManager, KeyManager, KeyManagerError},
    subject::Subject,
};

/// Struct for IONAttestor.
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
    /// Gets the signing keys of the attestor.
    fn signing_keys(&self) -> Result<OneOrMany<JWK>, KeyManagerError> {
        self.read_signing_keys(self.did_suffix())
    }

    /// Gets the signing key with ID `key_id` of the attestor.
    fn signing_key(&self, key_id: Option<&str>) -> Result<JWK, KeyManagerError> {
        let keys = self.signing_keys()?;
        // If no key_id is given, return the first available key.
        if let Some(key_id) = key_id {
            // Iterate over the available keys.
            for key in keys.into_iter() {
                // If the key has a key_id which matches the given key_id, return it.
                if let Some(this_key_id) = &key.key_id {
                    if this_key_id == key_id {
                        return Ok(key);
                    }
                }
            }
            // If none of the keys has a matching key_id, the required key does not exist.
            Err(KeyManagerError::FailedToLoadKey)
        } else {
            match keys.first() {
                Some(key) => Ok(key.to_owned()),
                None => Err(KeyManagerError::FailedToLoadKey),
            }
        }
    }
}

/// Type for holding attestor data.
pub struct AttestorData {
    did: String,
    signing_keys: OneOrMany<JWK>,
}

impl AttestorData {
    pub fn new(did: String, signing_keys: OneOrMany<JWK>) -> Self {
        Self { did, signing_keys }
    }
}

impl TryFrom<AttestorData> for IONAttestor {
    type Error = KeyManagerError;

    fn try_from(data: AttestorData) -> Result<Self, Self::Error> {
        let subject = IONAttestor { did: data.did };

        // Attempt to save the keys but do not overwrite existing key information.
        subject.save_keys(
            subject.did_suffix(),
            KeyType::SigningKey,
            &data.signing_keys,
            false,
        )?;
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

        // Add controller to document
        let mut doc = doc.clone();

        // Use full short-form DID as controller
        doc.controller = Some(OneOrMany::One(self.did().to_string()));

        // Canonicalize document
        let doc_canon = match ION::json_canonicalization_scheme(&doc) {
            Ok(str) => str,
            Err(_) => return Err(AttestorError::InvalidDocumentParameters(doc.id.clone())),
        };
        // Hash canonicalized document
        let doc_canon_hash = ION::hash(doc_canon.as_bytes());

        // Get the signing key.
        let signing_key = match self.signing_key(key_id) {
            Ok(key) => key,
            Err(_) => {
                if let Some(key_id) = key_id {
                    return Err(AttestorError::NoSigningKeyWithId(
                        self.did().to_string(),
                        key_id.to_string(),
                    ));
                } else {
                    return Err(AttestorError::NoSigningKey(self.did().to_string()));
                }
            }
        };
        // Encode and sign
        match ssi::jwt::encode_sign(algorithm, &doc_canon_hash, &signing_key) {
            Ok(str) => Ok(str),
            Err(e) => Err(AttestorError::SigningError(doc.id, e.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssi::did::Document;

    use trustchain_core::data::{TEST_SIGNING_KEYS, TEST_TRUSTCHAIN_DOCUMENT};
    use trustchain_core::utils::init;

    #[test]
    fn test_try_from() -> Result<(), Box<dyn std::error::Error>> {
        init();
        let signing_keys: OneOrMany<JWK> = serde_json::from_str(TEST_SIGNING_KEYS)?;
        let did = "did:example:did_try_from";
        let did_suffix = "did_try_from";

        let target =
            IONAttestor::try_from(AttestorData::new(did.to_string(), signing_keys.clone()))?;

        assert_eq!(target.did_suffix(), did_suffix);

        let loaded_signing_keys = target.signing_keys()?;
        assert_eq!(loaded_signing_keys, signing_keys);

        Ok(())
    }

    #[test]
    fn test_attest() -> Result<(), Box<dyn std::error::Error>> {
        // Initialize temp path for saving keys
        init();

        // Set-up keys and attestor
        let did = "did:example:test_attest";
        let keys: OneOrMany<JWK> = serde_json::from_str(TEST_SIGNING_KEYS)?;
        let (valid_key, invalid_key) = if let OneOrMany::Many(keys_vec) = &keys {
            (keys_vec.first().unwrap(), keys_vec.last().unwrap())
        } else {
            panic!()
        };
        let target = IONAttestor::try_from(AttestorData::new(did.to_string(), keys.clone()))?;

        // Load doc
        let doc = Document::from_json(TEST_TRUSTCHAIN_DOCUMENT).expect("Document failed to load.");

        // Attest to doc
        let result = target.attest(&doc, None);

        // Check attest was ok
        assert!(result.is_ok());

        // Check signature
        let proof_result = result?;
        let valid_decoded: Result<String, ssi::error::Error> =
            ssi::jwt::decode_verify(&proof_result, valid_key);
        let invalid_decoded: Result<String, ssi::error::Error> =
            ssi::jwt::decode_verify(&proof_result, invalid_key);
        assert!(valid_decoded.is_ok());
        assert!(invalid_decoded.is_err());

        // Check payload
        let valid_decoded = valid_decoded.unwrap();

        // Reconstruct doc
        let mut doc_with_controller = doc;
        doc_with_controller.controller = Some(OneOrMany::One(target.did().to_string()));
        let doc_canon = ION::json_canonicalization_scheme(&doc_with_controller)?;
        let doc_canon_hash = ION::hash(doc_canon.as_bytes());

        assert_eq!(valid_decoded, doc_canon_hash);

        Ok(())
    }

    #[test]
    fn test_signing_key() -> Result<(), Box<dyn std::error::Error>> {
        // Initialize temp path for saving keys
        init();

        // Set-up keys and attestor
        let did = "did:example:test_signing_key";

        // Load keys
        let mut keys: Vec<JWK> = serde_json::from_str(TEST_SIGNING_KEYS)?;

        // Attach key_id to keys
        for (i, key) in keys.iter_mut().enumerate() {
            if i == 0 {
                key.key_id = Some(format!("{}", i));
            }
        }
        let expected_key0 = keys[0].clone();
        let keys = OneOrMany::Many(keys);
        let target = IONAttestor::try_from(AttestorData::new(did.to_string(), keys))?;

        let actual_key = target.signing_key(None)?;
        assert_eq!(expected_key0, actual_key);

        let actual_key = target.signing_key(Some("0"))?;
        assert_eq!(expected_key0, actual_key);

        let actual_key_res = target.signing_key(Some("1"));
        let expected_res: Result<JWK, KeyManagerError> = Err(KeyManagerError::FailedToLoadKey);
        assert_eq!(actual_key_res, expected_res);

        Ok(())
    }
}
