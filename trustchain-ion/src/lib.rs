pub mod attest;
pub mod attestor;
pub mod controller;
pub mod create;
pub mod resolve;
use did_ion::{sidetree::SidetreeClient, ION};
use thiserror::Error;
use trustchain_core::resolver::{DIDMethodWrapper, Resolver};

/// Type alias
pub type IONResolver = Resolver<DIDMethodWrapper<SidetreeClient<ION>>>;

/// Test resolver
pub fn get_ion_resolver(endpoint: &str) -> IONResolver {
    IONResolver::from(SidetreeClient::<ION>::new(Some(String::from(endpoint))))
}

/// An error relating for rustchain-ion crate.
#[derive(Error, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TrustchainIONError {
    #[error("Key cannot be converted to commmitment value.")]
    FailedToConvertToCommitment,
    #[error("Commitment value could not be extracted from document metadata.")]
    FailedToExtractCommitment,
    #[error("Incorrect key type is provided.")]
    IncorrectKeyType,
}

// TODO: move to fixtures for trustchain-ion
const TEST_DOC_STATE: &str = r##"{
    "publicKeys": [
       {
          "id": "Mz94EfSCueClM5qv62SXxtLWRj4Ti7rR2wLWmW37aCs",
          "type": "JsonWebSignature2020",
          "publicKeyJwk": {
          "crv": "secp256k1",
          "kty": "EC",
          "x": "7VKmPezI_VEnMjOPfAeUnpQxhS1sLjAKfd0s7xrmx9A",
          "y": "gWZ5Bo197eZuMh3Se-3rqWCQjZWbuDpOYAaw8yC-yaQ"
          },
          "purposes": [
          "assertionMethod",
          "authentication",
          "keyAgreement",
          "capabilityInvocation",
          "capabilityDelegation"
          ]
       }
    ],
    "services": [
       {
          "id": "trustchain-controller-proof",
          "type": "TrustchainProofService",
          "serviceEndpoint": {
          "controller": "did:ion:test:EiA8yZGuDKbcnmPRs9ywaCsoE2FT9HMuyD9WmOiQasxBBg",
          "proofValue": "dummy_string"
          }
       }
    ]
 }"##;
