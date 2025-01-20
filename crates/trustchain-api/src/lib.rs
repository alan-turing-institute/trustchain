//! API for DID, VC and VP functionality.
pub mod api;
use crate::api::{TrustchainDIDAPI, TrustchainDataAPI, TrustchainVCAPI, TrustchainVPAPI};

/// A type for implementing CLI traits on.
pub struct TrustchainAPI;

impl TrustchainDIDAPI for TrustchainAPI {}
impl TrustchainVCAPI for TrustchainAPI {}
impl TrustchainVPAPI for TrustchainAPI {}
impl TrustchainDataAPI for TrustchainAPI {}

/// A template for data credentials.
/// Uses the dataset attribute from schema.org.
/// The context (i.e. ["https://schema.org/"](https://schema.org/)) is checked by the SSI library
/// against this [list](https://github.com/spruceid/ssi/blob/976e2607080c20cd5789b977e477e98b6417f8af/ssi-json-ld/src/lib.rs#L41)
/// with an exact string match. (Therefore the trailing "/" is required.)
pub(crate) const DATA_CREDENTIAL_TEMPLATE: &str = r###"
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
    "issuer": "did:ion:test:XYZ",
    "issuanceDate": "2000-01-01T00:00:00.0Z"
}
"###;
pub(crate) const DATA_ATTRIBUTE: &str = "dataset";
