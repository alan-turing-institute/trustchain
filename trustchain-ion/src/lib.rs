#![allow(dead_code)]
pub mod attestor;
// //! trustchain-ion library fns
// use did_ion::sidetree::Operation;

// TODO: move the create binary to a library function
// fn create(file_path: Option<&str>, verbose: bool) -> Operation {
//     // Move the binary logic into this fn

// }

pub mod controller;

use trustchain_core::key_manager::KeyManager;
pub struct KeyUtils;
impl KeyManager for KeyUtils {}

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
