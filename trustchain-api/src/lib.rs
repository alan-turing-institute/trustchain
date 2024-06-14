//! API for DID, VC and VP functionality.
pub mod api;
use crate::api::{TrustchainDIDAPI, TrustchainDataAPI, TrustchainVCAPI, TrustchainVPAPI};

/// A type for implementing CLI traits on.
pub struct TrustchainAPI;

impl TrustchainDIDAPI for TrustchainAPI {}
impl TrustchainVCAPI for TrustchainAPI {}
impl TrustchainVPAPI for TrustchainAPI {}
impl TrustchainDataAPI for TrustchainAPI {}

pub(crate) const DATASET_CREDENTIAL_TEMPLATE: &str = r#"
{
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://www.w3.org/2018/credentials/examples/v1",
      "https://schema.org/"
    ],
    "type": [
      "VerifiableCredential"
    ],
    "credentialSubject": {
      "dataset": ""
    },
    "issuer": "did:ion:test:EiDSE2lEM65nYrEqVvQO5C3scYhkv1KmZzq0S0iZmNKf1Q"
}
"#;
pub(crate) const DATASET_ATTRIBUTE: &str = "dataset";
pub(crate) const VC_XATTR_NAME: &str = "vc";
