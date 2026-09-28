//! Implementation of `Attestor` API for ION DID method.
use crate::ion::IONTest as ION;
use async_trait::async_trait;
use did_ion::sidetree::Sidetree;
use log::warn;
use ssi::did::Document;
use ssi::jsonld::ContextLoader;
use ssi::vc::{Credential, LinkedDataProofOptions, Presentation, URI};
use ssi::{
    jwk::{Algorithm, JWK},
    one_or_many::OneOrMany,
};
use std::convert::TryFrom;
use trustchain_core::holder::{Holder, HolderError};
use trustchain_core::issuer::{Issuer, IssuerError};
use trustchain_core::key_manager::KeyType;
use trustchain_core::resolver::TrustchainResolver;
use trustchain_core::vp::PresentationError;
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
    // TODO: made public to use in challenge-response. Consider refactoring key manager.
    pub fn signing_keys(&self) -> Result<OneOrMany<JWK>, KeyManagerError> {
        self.read_signing_keys(self.did_suffix())
    }

    /// Gets the first signing key matching a given `key_id` (by key ID or
    /// thumbprint) and `algorithm`, if given. Logs a warning if no matching
    /// key is found.
    // TODO: made public to use in challenge-response. Consider refactoring key manager.
    pub fn signing_key(
        &self,
        key_id: Option<&str>,
        algorithm: Option<Algorithm>,
    ) -> Result<JWK, KeyManagerError> {
        let keys = match self.signing_keys() {
            Ok(keys) => keys,
            Err(e) => {
                warn!("No signing key found belonging to {:?}.", self.did);
                return Err(e);
            }
        };
        // Iterate over the available keys and return the first that matches.
        for key_in_loop in keys.into_iter() {
            if let Some(algorithm) = algorithm {
                if key_in_loop.get_algorithm() != Some(algorithm) {
                    continue;
                }
            }
            if let Some(key_id) = key_id {
                // Match the given key_id against the key's ID or thumbprint.
                if key_in_loop.key_id.as_deref() != Some(key_id)
                    && key_in_loop.thumbprint()? != key_id
                {
                    continue;
                }
            }
            return Ok(key_in_loop);
        }
        // If none of the keys matches, the required key does not exist.
        let criteria = match (key_id, algorithm) {
            (None, None) => String::new(),
            (Some(key_id), None) => format!(" with ID {:?}", key_id),
            (None, Some(algorithm)) => format!(" with algorithm {:?}", algorithm),
            (Some(key_id), Some(algorithm)) => {
                format!(" with ID {:?} and algorithm {:?}", key_id, algorithm)
            }
        };
        warn!(
            "No signing key found{} belonging to {:?}.",
            criteria, self.did
        );
        Err(KeyManagerError::FailedToLoadKey)
    }
    /// Get the IONAttestor's public signing key.
    pub fn signing_pk(&self, key_id: Option<&str>) -> Result<JWK, KeyManagerError> {
        Ok(self.signing_key(key_id, None)?.to_public())
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
        let doc_canon = ION::json_canonicalization_scheme(&doc)
            .map_err(|_| AttestorError::InvalidDocumentParameters(doc.id.clone()))?;

        // Hash canonicalized document
        let doc_canon_hash = ION::hash(doc_canon.as_bytes());

        // Get the signing key.
        let signing_key = match self.signing_key(key_id, None) {
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

#[async_trait]
impl Issuer for IONAttestor {
    // Attests to a given credential returning the credential with proof. The `@context` of the credential has linked-data fields strictly checked as part of proof generation.
    async fn sign(
        &self,
        credential: &Credential,
        linked_data_proof_options: Option<LinkedDataProofOptions>,
        key_id: Option<&str>,
        algorithm: Option<Algorithm>,
        resolver: &dyn TrustchainResolver,
        context_loader: &mut ContextLoader,
    ) -> Result<Credential, IssuerError> {
        // Get the signing key.
        let signing_key = self.signing_key(key_id, algorithm)?;

        // Generate proof
        let proof = credential
            .generate_proof(
                &signing_key,
                &linked_data_proof_options.unwrap_or_default(),
                resolver.as_did_resolver(),
                context_loader,
            )
            .await?;

        // Add proof to credential
        let mut vc = credential.clone();
        vc.add_proof(proof);
        Ok(vc)
    }
}

#[async_trait]
impl Holder for IONAttestor {
    // This implementation ensures that the holder field is set on the Presentation, with the
    // following implications:
    //   - proof generation is handled by the ssi library
    //   - ssi::ldp::ensure_or_pick_verification_relationship calls presentation.get_issuer()
    //      which returns the holder (if Some, which is always the case)
    //   - ensure_or_pick_verification_relationship tries to resolve the holder DID and check its
    //      verification methods
    //   - so the holder's DID must be resolvable
    async fn sign_presentation(
        &self,
        presentation: &Presentation,
        linked_data_proof_options: Option<LinkedDataProofOptions>,
        key_id: Option<&str>,
        resolver: &dyn TrustchainResolver,
        context_loader: &mut ContextLoader,
    ) -> Result<Presentation, PresentationError> {
        // If no ldp options passed, use default with ProofPurpose::Authentication.
        let options = linked_data_proof_options.unwrap_or(LinkedDataProofOptions {
            proof_purpose: Some(ssi::vc::ProofPurpose::Authentication),
            ..Default::default()
        });

        // Get the signing key.
        let signing_key = self
            .signing_key(key_id, None)
            .map_err(HolderError::KeyManager)?;

        let mut vp = presentation.clone();
        // Check holder field is correctly populated
        match presentation.holder.as_ref() {
            Some(URI::String(holder)) => {
                if holder != &self.did {
                    return Err(HolderError::MismatchedHolder.into());
                }
            }
            None => vp.holder = Some(URI::String(self.did.clone())),
        };

        // Generate proof
        let proof = vp
            .generate_proof(&signing_key, &options, resolver, context_loader)
            .await?;
        // Add proof to credential
        vp.add_proof(proof);
        Ok(vp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trustchain_resolver;
    use crate::utils::init;
    use crate::utils::BITCOIN_NETWORK;
    use bitcoin::Network;
    use ssi::did::Document;
    use ssi::vc::CredentialOrJWT;
    use trustchain_core::data::{TEST_CREDENTIAL, TEST_SIGNING_KEYS, TEST_TRUSTCHAIN_DOCUMENT};

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
        let valid_decoded: Result<String, ssi::jws::Error> =
            ssi::jwt::decode_verify(&proof_result, valid_key);
        let invalid_decoded: Result<String, ssi::jws::Error> =
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

    #[tokio::test]
    async fn test_attest_credential() {
        // Initialize temp path for saving keys
        init();

        // Resolver
        let resolver = trustchain_resolver("http://localhost:3000/");

        // Set-up keys and attestor
        let did = "did:example:test_attest_credential";
        // Attestor
        let target = IONAttestor::try_from(AttestorData::new(
            did.to_string(),
            serde_json::from_str(TEST_SIGNING_KEYS).unwrap(),
        ))
        .unwrap();

        // Load credential. Issuer is "None" here so no resolution is required.
        let vc = serde_json::from_str(TEST_CREDENTIAL).unwrap();

        // Attest to doc
        let vc_with_proof = target
            .sign(
                &vc,
                None,
                None,
                None,
                &resolver,
                &mut ContextLoader::default(),
            )
            .await;

        // Check attest was ok
        assert!(vc_with_proof.is_ok());
    }

    #[ignore = "requires a running Sidetree node listening on http://localhost:3000"]
    #[tokio::test]
    async fn test_sign_credential_failure() {
        // Initialize temp path for saving keys
        init();

        // 1. Set-up (with a DID that will *not* match the issuer field in the credential).
        let did = "did:ion:test:EiDMe2SFfJ_7eXVW7RF1ZHOkeu2M-Bre0ak2cXNBH0P-TQ";

        // Make resolver
        let resolver = trustchain_resolver("http://localhost:3000/");

        // 2. Load Attestor
        // Attestor
        let attestor = IONAttestor::try_from(AttestorData::new(
            did.to_string(),
            serde_json::from_str(TEST_SIGNING_KEYS).unwrap(),
        ))
        .unwrap();

        // 3. Read credential and set issuer field
        let issuer_did = match BITCOIN_NETWORK
            .as_ref()
            .expect("Integration test requires Bitcoin")
        {
            Network::Testnet => "did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q",
            Network::Testnet4 => "did:ion:test:EiAhwHOB5rQX8yPvJW6NI7wvppM1TiMuvnJ5oW5_AkxbNg",
            network @ _ => {
                panic!("No test fixtures for network: {:?}", network);
            }
        };

        let mut vc: Credential = serde_json::from_str(TEST_CREDENTIAL).unwrap();
        vc.issuer = Some(ssi::vc::Issuer::URI(URI::String(issuer_did.to_string())));

        // Sign credential (expect failure).
        // Note: Signing a vc with a Some() issuer field requires a running ion node
        let vc_with_proof = attestor
            .sign(
                &vc,
                None,
                None,
                None,
                &resolver,
                &mut ContextLoader::default(),
            )
            .await;
        assert!(vc_with_proof.is_err());

        // Check error matches
        assert!(matches!(
            vc_with_proof,
            Err(IssuerError::LDP(ssi::ldp::Error::DID(
                ssi::did::Error::KeyMismatch
            )))
        ))
    }

    #[ignore = "requires a running Sidetree node listening on http://localhost:3000"]
    #[tokio::test]
    async fn test_attest_presentation() {
        init();
        let resolver = trustchain_resolver("http://localhost:3000/");

        let (issuer_did, holder_did) = match BITCOIN_NETWORK
            .as_ref()
            .expect("Integration test requires Bitcoin")
        {
            Network::Testnet => (
                "did:ion:test:EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A",
                "did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q",
            ),
            Network::Testnet4 => (
                "did:ion:test:EiBijhXD8AGKu891yTssu69qRwwC46IfOphnfI9XzXQp5Q",
                "did:ion:test:EiBdezm5h0cCTfeoDjKoFrpc6cf2Np4RoMSbFyEel-u8og",
            ),
            network @ _ => {
                panic!("No test fixtures for network: {:?}", network);
            }
        }; // (root+1, root+2)

        let issuer = IONAttestor::new(issuer_did);
        let holder = IONAttestor::new(holder_did);

        let vc = serde_json::from_str(TEST_CREDENTIAL).unwrap();
        let vc_with_proof = issuer
            .sign(
                &vc,
                None,
                None,
                None,
                &resolver,
                &mut ContextLoader::default(),
            )
            .await
            .unwrap();

        // Create Presentation, initially with holder field defaulting to None
        let presentation = Presentation {
            verifiable_credential: Some(OneOrMany::One(CredentialOrJWT::Credential(vc_with_proof))),
            ..Default::default()
        };

        // Holder field set to the DID of the signing holder by 'sign_presentation'
        // The DID is resolved during signing, which requires a running ion node.
        let vp = holder
            .sign_presentation(
                &presentation,
                None,
                None,
                &resolver,
                &mut ContextLoader::default(),
            )
            .await;

        assert!(vp.is_ok());
    }

    #[test]
    fn test_signing_key() -> Result<(), Box<dyn std::error::Error>> {
        // Initialize temp path for saving keys
        init();

        // Set-up keys and attestor
        let did = "did:example:test_signing_key";

        // Load keys
        let mut keys: Vec<JWK> = serde_json::from_str(TEST_SIGNING_KEYS)?;

        // Attach a key_id to first key only
        keys.first_mut().map(|key| {
            key.key_id = Some("0".to_string());
            key
        });
        let expected_key = keys.first().unwrap().clone();

        // Target
        let target =
            IONAttestor::try_from(AttestorData::new(did.to_string(), OneOrMany::Many(keys)))?;

        // With None passed, expect first key
        let actual_key = target.signing_key(None, None)?;
        assert_eq!(expected_key, actual_key);

        // With key_id passed, expect correct key returned
        let actual_key = target.signing_key(Some("0"), None)?;
        assert_eq!(expected_key, actual_key);

        // With a non-matching key_id, expect KeyManagerError::FailedToLoadKey
        let actual_key_res = target.signing_key(Some("1"), None);
        assert!(matches!(
            actual_key_res,
            Err(KeyManagerError::FailedToLoadKey)
        ));
        Ok(())
    }

    #[test]
    fn test_signing_key_with_algorithm() -> Result<(), Box<dyn std::error::Error>> {
        // Initialize temp path for saving keys
        init();

        // Set-up keys and attestor
        let did = "did:example:test_signing_key_with_algorithm";

        // Load keys (both secp256k1, so inferred algorithm is ES256K)
        let mut keys: Vec<JWK> = serde_json::from_str(TEST_SIGNING_KEYS)?;

        // Attach a key_id to first key and set an explicit algorithm on last key only
        keys.first_mut().unwrap().key_id = Some("0".to_string());
        keys.last_mut().unwrap().algorithm = Some(Algorithm::RSS2023);
        let first_key = keys.first().unwrap().clone();
        let last_key = keys.last().unwrap().clone();

        // Target
        let target =
            IONAttestor::try_from(AttestorData::new(did.to_string(), OneOrMany::Many(keys)))?;

        // With an algorithm passed, expect first key with that algorithm
        let actual_key = target.signing_key(None, Some(Algorithm::ES256K))?;
        assert_eq!(first_key, actual_key);
        let actual_key = target.signing_key(None, Some(Algorithm::RSS2023))?;
        assert_eq!(last_key, actual_key);

        // With key_id and algorithm passed, expect key matching both
        let thumbprint = last_key.thumbprint()?;
        let actual_key = target.signing_key(Some(&thumbprint), Some(Algorithm::RSS2023))?;
        assert_eq!(last_key, actual_key);

        // With a non-matching algorithm, expect KeyManagerError::FailedToLoadKey
        let actual_key_res = target.signing_key(None, Some(Algorithm::EdDSA));
        assert!(matches!(
            actual_key_res,
            Err(KeyManagerError::FailedToLoadKey)
        ));

        // With a key_id whose key does not match the algorithm, expect KeyManagerError::FailedToLoadKey
        let actual_key_res = target.signing_key(Some("0"), Some(Algorithm::RSS2023));
        assert!(matches!(
            actual_key_res,
            Err(KeyManagerError::FailedToLoadKey)
        ));
        Ok(())
    }

    #[test]
    fn test_signing_key_with_thumbprint() -> Result<(), Box<dyn std::error::Error>> {
        // Initialize temp path for saving keys
        init();

        // Set-up keys and attestor
        let did = "did:example:test_signing_with_thumbrint_key";

        // Load keys
        let keys: Vec<JWK> = serde_json::from_str(TEST_SIGNING_KEYS)?;
        let expected_key = keys.last().unwrap().clone();

        let target =
            IONAttestor::try_from(AttestorData::new(did.to_string(), OneOrMany::Many(keys)))?;

        // With thumbprint passed, expect correct key returned.
        let actual_key = target.signing_key(Some(&expected_key.thumbprint().unwrap()), None)?;
        assert_eq!(expected_key, actual_key);

        Ok(())
    }
}
