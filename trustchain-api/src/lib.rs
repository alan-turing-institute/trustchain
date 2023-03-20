use anyhow;
use did_ion::sidetree::DocumentState;
use ssi::{jwk::JWK, vc::Credential};
use std::error::Error;
use trustchain_core::{chain::DIDChain, verifier::VerifierError};

/// API for Trustchain CLI DID functionality.
pub trait TrustchainDIDCLI {
    /// Creates a controlled DID from a passed document state, writing the associated create operation to file in the operations path.
    fn create(document_state: Option<DocumentState>, verbose: bool) -> Result<(), Box<dyn Error>>;
    /// An uDID attests to a dDID, writing the associated update operation to file in the operations path.
    fn attest(did: &str, controlled_did: &str, verbose: bool) -> Result<(), Box<dyn Error>>;
    /// Resolves a given DID using a resolver available at localhost:3000
    fn resolve(did: &str, verbose: bool) -> Result<(), Box<dyn Error>>;

    /// TODO: the below have no CLI implementation currently but are planned
    /// Verifies a given DID using a resolver available at localhost:3000, returning a result.
    fn verify(did: &str, verbose: bool) -> Result<DIDChain, VerifierError>;
    /// Generates an update operation and writes to operations path.
    fn update(did: &str, controlled_did: &str, verbose: bool) -> Result<(), Box<dyn Error>>;
    /// Generates a recover operation and writes to operations path.
    fn recover(did: &str, verbose: bool) -> Result<(), Box<dyn Error>>;
    /// Generates a deactivate operation and writes to operations path.
    fn deactivate(did: &str, verbose: bool) -> Result<(), Box<dyn Error>>;
    /// Publishes operations within the operations path (queue).
    fn publish(did: &str, verbose: bool) -> Result<(), Box<dyn Error>>;
}

/// API for Trustchain CLI VC functionality.
pub trait TrustchainVCCLI {
    /// Signs a credential
    fn sign(credential: &Credential, did: &str, key: &JWK) -> Credential;
    /// Verifies a credential
    fn verify(credential: &Credential, did: &str, key: &JWK) -> Result<(), Box<dyn Error>>;
}

/// API for Trustchain mobile functionality.
pub trait TrustchainMobileFFI {
    /// Resolves a given DID assuming trust in endpoint.
    fn did_resolve(did: String) -> String;
    /// Verifies a given DID assuming trust in endpoint.
    fn did_verify(did: String) -> String;
    /// Verifies a given DID bundle providing complete verification without trust in endpoint.
    fn did_verify_bundle(bundle_json: String) -> String;
    /// Verifies a verifiable credential. Analogous with [didkit](https://docs.rs/didkit/latest/didkit/c/fn.didkit_vc_verify_credential.html).
    fn vc_verify_credential(credential_json: String, proof_options_json: String) -> String;
    /// Issues a verifiable presentation. Analogous with [didkit](https://docs.rs/didkit/latest/didkit/c/fn.didkit_vc_issue_presentation.html).
    fn vc_issue_presentation(
        presentation_json: String,
        proof_options_json: String,
        key_json: String,
    );
    /// Verifies a verifiable presentation. Analogous with [didkit](https://docs.rs/didkit/latest/didkit/c/fn.didkit_vc_verify_presentation.html).
    fn vc_verify_presentation(presentation_json: String, proof_options_json: String) -> String;
}

/// API for Trustchain GUI functionality.
pub trait TrustchainGUIFFI {
    /// Set up to mirror the CLI functionality
    /// NOTE: There is currently an open pull request for support of the rust Result type which will add the functionality
    /// of returning custom error types rather than only a custom error message (&str).

    /// Creates a controlled DID from a passed document state, writing the associated create operation to file in the operations path.
    fn create(document_state: Option<String>, verbose: bool) -> anyhow::Result<()>;
    /// An uDID attests to a dDID, writing the associated update operation to file in the operations path.
    fn attest(did: String, controlled_did: String, verbose: bool) -> anyhow::Result<()>;
    /// Resolves a given DID using a resolver available at localhost:3000
    fn resolve(did: String, verbose: bool) -> anyhow::Result<()>;

    /// TODO: the below have no CLI implementation currently but are planned
    /// Verifies a given DID using a resolver available at localhost:3000, returning a result.
    fn verify(did: String, verbose: bool) -> anyhow::Result<DIDChain>;
    /// Generates an update operation and writes to operations path.
    fn update(did: String, controlled_did: String, verbose: bool) -> anyhow::Result<()>;
    /// Generates a recover operation and writes to operations path.
    fn recover(did: String, verbose: bool) -> anyhow::Result<()>;
    /// Generates a deactivate operation and writes to operations path.
    fn deactivate(did: String, verbose: bool) -> anyhow::Result<()>;
    /// Publishes operations within the operations path (queue).
    fn publish(did: String, verbose: bool) -> anyhow::Result<()>;
}

/// API for Trustchain server functionality.
pub trait TrustchainHTTP {}

#[cfg(test)]
mod tests {
    use super::*;
}
