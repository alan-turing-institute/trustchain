//! Verifiable credential functionality for Trustchain.
use crate::vc_encoding::CanonicalFlatten;
use crate::verifier::VerifierError;
use ps_sig::{
    keys::{PKrss, PKrssError},
    message_structure::message_encode::EncodedMessages,
    rsssig::{RSVerifyResult, RSignature, RSignatureError},
};
use ssi::{
    ldp::Proof,
    vc::{Credential, VerificationResult},
};

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
    /// Missing verification method in credential proof.
    #[error("Missing verification method in credential proof.")]
    MissingVerificationMethod,
    /// Failed to decode JWT error.
    #[error("Failed to decode JWT.")]
    FailedToDecodeJWT,
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

/// Owned interface for proof verifcation across different proof suites. A simplified reimplementation
///  of ssi::ldp::ProofSuite, including only the verification method and simplifying the api to
/// constrain the &dyn LinkedDataDocument to a &Credential.
/// An owned trait is required to avoid the orphan rule, when implementing this trait for RSS
/// signatures (an external crate)
pub trait ProofVerify {
    fn verify_proof(proof: &Proof, credential: &Credential) -> Result<(), ProofVerifyError>;
}

/// An error relating to proof verification.
#[derive(Error, Debug)]
pub enum ProofVerifyError {
    /// No verification method present in proof.
    #[error("Missing verification method.")]
    MissingVerificationMethod,
    /// No proof value present in proof.
    #[error("Missing proof value.")]
    MissingProofValue,
    /// Wrapped error for PKrssError.
    #[error("A wrapped PKrssError: {0}")]
    PKrssError(PKrssError),
    /// Wrapped error for RSignatureError.
    #[error("A wrapped RSignatureError: {0}")]
    RSignatureError(RSignatureError),
    /// Wrapped RSVerifyResult for RSignature verification.
    #[error("A wrapped RSVerifyResult error: {0}")]
    RSVerifyResultError(RSVerifyResult),
}

impl From<RSVerifyResult> for ProofVerifyError {
    fn from(value: RSVerifyResult) -> Self {
        ProofVerifyError::RSVerifyResultError(value)
    }
}

impl From<RSignatureError> for ProofVerifyError {
    fn from(value: RSignatureError) -> Self {
        ProofVerifyError::RSignatureError(value)
    }
}

impl Into<VerificationResult> for ProofVerifyError {
    fn into(self) -> VerificationResult {
        VerificationResult::error(&self.to_string())
    }
}

impl ProofVerify for RSignature {
    fn verify_proof(proof: &Proof, credential: &Credential) -> Result<(), ProofVerifyError> {
        // If there is a signature
        if let Some(sig_ser) = &proof.proof_value {
            // Parse from Hex
            let rsig = Self::from_hex(&sig_ser)?;
            // Parse public key from verification method on Proof
            let pkrss = PKrss::from_hex(
                &proof
                    .verification_method
                    .as_ref()
                    .ok_or(ProofVerifyError::MissingVerificationMethod)?,
            )
            .map_err(|e| ProofVerifyError::PKrssError(e))?;
            // Encode credential into sequence of FieldElements
            let messages: EncodedMessages = credential.flatten().into();
            let res = RSignature::verifyrsignature(
                &pkrss,
                &rsig,
                messages.as_slice(),
                &messages.infered_idxs,
            );
            if let RSVerifyResult::Valid = res {
                Ok(())
            } else {
                Err(res.into())
            }
        } else {
            Err(ProofVerifyError::MissingProofValue)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{vc::ProofVerify, vc_encoding::CanonicalFlatten};
    use ps_sig::{
        keys::{rsskeygen, Params},
        message_structure::message_encode::EncodedMessages,
        rsssig::RSignature,
    };
    use ssi::{ldp::Proof, vc::Credential};

    const TEST_UNSIGNED_VC: &str = r##"{
        "@context": [
          "https://www.w3.org/2018/credentials/v1",
          "https://www.w3.org/2018/credentials/examples/v1",
          "https://w3id.org/citizenship/v1"
        ],
        "type": ["VerifiableCredential"],
        "issuer": "did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q",
        "credentialSubject": {
          "givenName": "Jane",
          "familyName": "Doe",
          "degree": {
            "type": "BachelorDegree",
            "name": "Bachelor of Science and Arts",
            "college": "College of Engineering"
          }
        }
      }
      "##;

    #[test]
    fn verify_rss_signature() {
        // create rss keypair
        let (sk, pk) = rsskeygen(10, &Params::new("test".as_bytes()));
        // load complete (unredacted) vc
        let vc: Credential = serde_json::from_str(TEST_UNSIGNED_VC).unwrap();
        // flatten and encode
        let messages = EncodedMessages::from(vc.flatten());
        // check that the vc has been infered to include 6 (all) fields
        assert_eq!(6, messages.infered_idxs.len());
        // generate RSS signature
        let rsig = RSignature::new(messages.as_slice(), &sk);
        // generate proof from RSS signature
        let mut proof = Proof::new("RSSSignature");
        proof.proof_value = Some(rsig.to_hex());
        proof.verification_method = Some(pk.to_hex());
        // verify proof
        assert!(RSignature::verify_proof(&proof, &vc).is_ok());
    }
}
