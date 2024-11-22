//! Types for store items.
use serde::{Deserialize, Serialize};
use ssi::vc::Credential;

/// Credential store item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialStoreItem {
    #[serde(rename = "did")]
    pub issuer_did: String,
    pub credential: Credential,
}
