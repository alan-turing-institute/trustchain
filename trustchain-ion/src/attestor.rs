use std::convert::TryFrom;

use async_trait::async_trait;
use did_ion::sidetree::Sidetree;
use did_ion::ION;
use ssi::did::Document;
use ssi::did_resolve::DIDResolver;
use ssi::vc::{Credential, LinkedDataProofOptions};
use ssi::{jwk::JWK, one_or_many::OneOrMany};
use trustchain_core::attestor::CredentialAttestor;
use trustchain_core::get_did_suffix;
use trustchain_core::key_manager::KeyType;
use trustchain_core::resolver::Resolver;
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
        self.read_signing_keys(self.did_suffix())
    }

    /// Get the IONAttestor's signing key.
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
    /// Get the IONAttestor's public signing key.
    pub fn signing_pk(&self, key_id: Option<&str>) -> Result<JWK, KeyManagerError> {
        match self.signing_key(key_id) {
            Ok(key) => Ok(key.to_public()),
            Err(e) => Err(e),
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
    type Error = Box<dyn std::error::Error>;

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
    fn did_suffix(&self) -> &str {
        get_did_suffix(&self.did)
    }
}

impl Attestor for IONAttestor {
    fn attest(
        &self,
        doc: &Document,
        key_id: Option<&str>,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let algorithm = ION::SIGNATURE_ALGORITHM;

        // Add controller to document
        let mut doc = doc.clone();

        // Use full short-form DID as controller
        doc.controller = Some(OneOrMany::One(self.did().to_string()));

        // Canonicalize document
        let doc_canon = match ION::json_canonicalization_scheme(&doc) {
            Ok(str) => str,
            Err(_) => {
                return Err(Box::new(AttestorError::InvalidDocumentParameters(
                    doc.id.clone(),
                )))
            }
        };
        // Hash canonicalized document
        let doc_canon_hash = ION::hash(doc_canon.as_bytes());

        // Get the signing key.
        let signing_key = self.signing_key(key_id)?;

        // Encode and sign
        match ssi::jwt::encode_sign(algorithm, &doc_canon_hash, &signing_key) {
            Ok(str) => Ok(str),
            Err(e) => Err(Box::new(AttestorError::SigningError(
                doc.id.clone(),
                e.to_string(),
            ))),
        }
    }

    /// Attests to a passed string slice.
    fn attest_str(
        &self,
        doc: &str,
        key_id: Option<&str>,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let algorithm = ION::SIGNATURE_ALGORITHM;

        // Hash canonicalized document
        let doc_canon_hash = ION::hash(doc.as_bytes());

        // Get the signing key.
        let signing_key = self.signing_key(key_id)?;

        // Encode and sign
        // TODO: check use of jws: seems correct as payload is a hash not a JSON.
        match ssi::jws::detached_sign_unencoded_payload(
            algorithm,
            doc_canon_hash.as_bytes(),
            &signing_key,
        ) {
            Ok(str) => Ok(str),
            Err(e) => Err(Box::new(AttestorError::SigningError(
                self.did().to_string(),
                e.to_string(),
            ))),
        }
    }
}

#[async_trait]
impl CredentialAttestor for IONAttestor {
    // Attests to a passed credential returning the credential with proof.
    async fn attest_credential(
        &self,
        doc: &Credential,
        key_id: Option<&str>,
        resolver: &dyn DIDResolver,
    ) -> Result<Credential, Box<dyn std::error::Error>> {
        // Get the signing key.
        let signing_key = self.signing_key(key_id)?;
        // Generate proof
        let proof = doc
            .generate_proof(&signing_key, &LinkedDataProofOptions::default(), resolver)
            .await;
        // Handle proof result
        match proof {
            Ok(proof) => {
                let mut doc_with_proof = doc.clone();
                doc_with_proof.add_proof(proof);
                Ok(doc_with_proof)
            }
            Err(e) => Err(Box::new(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_resolver;
    use ssi::did::Document;
    use ssi::jws::detached_verify;
    use ssi::vc::Proof;
    use trustchain_core::data::{TEST_CREDENTIAL, TEST_SIGNING_KEYS, TEST_TRUSTCHAIN_DOCUMENT};
    use trustchain_core::init;
    use trustchain_core::utils::canonicalize;

    #[test]
    fn test_try_from() -> Result<(), Box<dyn std::error::Error>> {
        init();
        assert_eq!(0, 0);
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
    fn test_attest_str() -> Result<(), Box<dyn std::error::Error>> {
        // Initialize temp path for saving keys
        init();

        // Set-up keys and attestor
        let did = "did:example:test_attest_str";
        let signing_keys: OneOrMany<JWK> = serde_json::from_str(TEST_SIGNING_KEYS)?;

        // 2. Load Attestor
        let attestor = IONAttestor::try_from(AttestorData::new(did.to_string(), signing_keys))?;

        // 3. Read credential
        let mut vc: Credential = serde_json::from_str(TEST_CREDENTIAL)?;

        // 4. Canonicalize and attest
        let vc_canon = canonicalize(&vc)?;

        // 5. Get a detached JWS signature for VC
        let proof = attestor.attest_str(&vc_canon, None);
        assert!(proof.is_ok());

        // Unwrap attestation proof
        let proof = proof.unwrap();

        // 6. Set proof property
        vc.proof = Some(OneOrMany::One(Proof {
            jws: Some(proof.clone()),
            ..Default::default()
        }));

        // 7. Verify
        let signing_pk = attestor.signing_key(None).unwrap().to_public();

        // Check the signature is valid by passing in the payload and detached signature
        let det_ver = detached_verify(
            &proof,
            ION::hash(vc_canon.as_bytes()).as_bytes(),
            &signing_pk,
        );
        assert!(det_ver.is_ok());

        Ok(())
    }

    #[test]
    #[ignore = "requires a running Sidetree node listening on http://localhost:3000"]
    fn test_attest_credential() -> Result<(), Box<dyn std::error::Error>> {
        // Initialize temp path for saving keys
        init();

        // Get resolver
        let resolver = test_resolver("http://localhost:3000/");

        // Set-up keys and attestor
        let did = "did:example:test_attest_credential";
        let keys: OneOrMany<JWK> = serde_json::from_str(TEST_SIGNING_KEYS)?;
        let target = IONAttestor::try_from(AttestorData::new(did.to_string(), keys))?;

        // Load credential
        let doc: Credential = serde_json::from_str(TEST_CREDENTIAL)?;

        // async function run within runtime
        resolver.runtime.block_on(async {
            // Get credential with proof
            let doc_with_proof = target
                .attest_credential(&doc, None, &resolver)
                .await
                .unwrap();

            // Assert credential has proof
            assert!(doc_with_proof.proof.is_some());
        });
        Ok(())
    }

    // #[test]
    // fn test_signing_key() {}
}
