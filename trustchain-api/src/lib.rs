use did_ion::sidetree::DocumentState;
use ssi::{did_resolve::ResolutionResult, jwk::JWK, vc::Credential, vc::Presentation};
use std::error::Error;
use trustchain_core::{chain::DIDChain, verifier::VerifierError};

// TODO: Should we implement any of these traits as subtraits/supertraits?

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
pub trait TrustchainGUIFFI {}

// TODO: add implementation here from Trustchain server crate.
pub struct DIDChainResolutionResult;

/// API for Trustchain server functionality. The associated handlers required for the endpoint.
pub trait TrustchainHTTP {
    /// Resolves a DID chain, will this include the bundle?
    fn resolve_chain(did: &str) -> DIDChainResolutionResult;
    /// Resolves a DID chain, will this include the bundle?
    fn resolve_did(did: &str) -> ResolutionResult;

    // TODO: should we include a separate method to return verification bundle?
    fn resolve_bundle();
}

// TODO: implement with data required for a valid credential offer
/// A type for describing credential offers.
pub struct CredentialOffer;

/// An API for a Trustchain verifier server.
pub trait TrustchainIssuerHTTP {
    // pub trait TrustchainIssuerHTTP : TrustchainHTTP + TrustchainDIDCLI + TrustchainVCCLI {
    /// Issues an offer for a verifiable credential
    // TODO: should this be a String or its own type (e.g. `CredentialOffer`)
    fn generate_credential_offer(template: &Credential, credential_id: &str) -> CredentialOffer;
    /// Issues a verfiable credential (should it return `Credential` or `String`)
    fn issue_credential(template: &Credential, subject_id: &str, credential_id: &str)
        -> Credential;
}

// TODO: implement in core?
pub struct PresentationRequest;

// TODO: implement in core?
/// An error type for presentation failures
pub enum PresentationError {
    FailedToVerify,
    // TODO: add other variants
}

/// An API for a Trustchain verifier server.
pub trait TrustchainVerifierHTTP {
    /// Constructs a presentation request (given some `presentiation_id`) to send to a credential holder from request wallet by ID
    fn generate_presentation_request(presentation_id: &str) -> PresentationRequest;
    /// Verifies verifiable presentation
    fn verify_presentation(presentation: &Presentation) -> Result<(), PresentationError>;
    /// Verifies verifiable credential
    fn verify_credential(credential: &Credential) -> Result<(), PresentationError>;
}

#[cfg(test)]
mod tests {
    use super::*;
}
