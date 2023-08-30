//! Verifiable credential functionality for Trustchain.
use crate::verifier::VerifierError;
use ps_sig::rsssig::RSignature;
use ssi::vc::{Credential, Proof, VerificationResult};
use thiserror::Error;

/// An error relating to verifiable credentials and presentations.
#[derive(Error, Debug)]
pub enum CredentialError {
    /// No issuer present in credential.
    #[error("No issuer.")]
    NoIssuerPresent,
    /// No proof present in credential.
    #[error("No proof.")]
    NoProofPresent,
    /// Wrapped error for Verifier error.
    #[error("A wrapped Verifier error: {0}")]
    VerifierError(VerifierError),
    /// Wrapped verification result with errors.
    #[error("A wrapped verification result error: {0:?}")]
    VerificationResultError(VerificationResult),
}

impl From<VerifierError> for CredentialError {
    fn from(err: VerifierError) -> Self {
        CredentialError::VerifierError(err)
    }
}

/// More flexible interface (compared to ssi::ldp::ProofSuite) to implement verification of
/// `ssi::vc::Proof`s for new proof types (with access to the credential fields, which is required
/// in the case of RSS proofs)
pub trait ProofVerify {
    // TODO: is ssi::vc::Proof the same as ssi::vp::Proof?
    fn verify_proof(proof: &Proof, credential: &Credential) -> VerificationResult;
}

impl ProofVerify for RSignature {
    fn verify_proof(proof: &Proof, credential: &Credential) -> VerificationResult {
        VerificationResult::new()
    }
}

#[cfg(test)]
mod tests {}
