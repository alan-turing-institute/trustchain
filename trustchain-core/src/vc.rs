//! Verifiable credential functionality for Trustchain.
use crate::vc_encoding::CanonicalFlatten;
use crate::verifier::VerifierError;
use ps_sig::{
    keys::{PKrss, PKrssError},
    message_structure::message_encode::EncodedMessages,
    rsssig::{RSVerifyResult, RSignature},
};
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
    #[error("A wrapped PKrssError.")]
    WrappedPKrssError(PKrssError),
    /// Wrapped RSVerifyResult for RSignature verification.
    #[error("A wrapped RSVerifyResult error: {0}")]
    WrappedRSVerifyResultError(RSVerifyResult),
}

impl From<RSVerifyResult> for ProofVerifyError {
    fn from(value: RSVerifyResult) -> Self {
        ProofVerifyError::WrappedRSVerifyResultError(value)
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
            let rsig = Self::from_hex(&sig_ser);
            // Parse public key from verification method on Proof
            let pkrss = PKrss::from_hex(
                &proof
                    .verification_method
                    .as_ref()
                    .ok_or(ProofVerifyError::MissingVerificationMethod)?,
            )
            .map_err(|e| ProofVerifyError::WrappedPKrssError(e))?;
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
    use crate::{
        vc::ProofVerify,
        vc_encoding::{CanonicalFlatten, RedactValues},
    };
    use ps_sig::{
        keys::{rsskeygen, PKrss, Params},
        message_structure::message_encode::EncodedMessages,
        rsssig::RSignature,
    };
    use ssi::vc::{Credential, Proof};

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

    #[test]
    fn verify_redacted_rss_signature() {
        // chose indicies to disclose
        let idxs = vec![2, 3, 6];

        // obtain a vc with an RSS proof
        let signed_vc = issue_rss_vc();
        println!("{}", serde_json::to_string_pretty(&signed_vc).unwrap());

        // produce a Vec<String> representation of the VC with only the selected fields disclosed
        let mut redacted_seq = signed_vc.flatten();
        redacted_seq.redact(&idxs).unwrap();
        println!("{}", serde_json::to_string_pretty(&redacted_seq).unwrap());

        // encode redacted sequence into FieldElements
        let messages = EncodedMessages::from(redacted_seq);

        // parse issuers PK from the proof on the signed vc
        let issuers_proofs = signed_vc.proof.as_ref().unwrap();
        let issuers_pk = PKrss::from_hex(
            &issuers_proofs
                .first()
                .unwrap()
                .verification_method
                .as_ref()
                .unwrap(),
        )
        .unwrap();

        // derive redacted RSignature
        let r_rsig = RSignature::from_hex(
            &issuers_proofs
                .first()
                .unwrap()
                .proof_value
                .as_ref()
                .unwrap(),
        )
        .derive_signature(
            &issuers_pk,
            EncodedMessages::from(signed_vc.flatten()).as_slice(),
            &messages.infered_idxs,
        );

        // generate proof from derived RSS signature
        let mut proof = Proof::new("RSSSignature");
        proof.proof_value = Some(r_rsig.to_hex());
        proof.verification_method = Some(issuers_pk.to_hex());

        // produce an unsigned, redacted vc
        let mut redacted_vc = signed_vc;
        redacted_vc.proof = None;
        redacted_vc.redact(&idxs).unwrap();

        // the redacted vc **with** a proof could now be assembled from the redacted_vc and
        // the proof, but the verification of the Credential will ultimately call the following:
        assert!(RSignature::verify_proof(&proof, &redacted_vc).is_ok());
        // println!(
        //     "{:?}",
        //     RSignature::verify_proof(&proof, &redacted_unsigned_vc)
        // )
    }

    fn issue_rss_vc() -> Credential {
        // create rss keypair
        let (sk, pk) = rsskeygen(10, &Params::new("test".as_bytes()));
        // load complete (unredacted) vc
        let mut vc: Credential = serde_json::from_str(TEST_UNSIGNED_VC).unwrap();
        let rsig = RSignature::new(EncodedMessages::from(vc.flatten()).as_slice(), &sk);
        let mut proof = Proof::new("RSSSignature");
        proof.proof_value = Some(rsig.to_hex());
        proof.verification_method = Some(pk.to_hex());
        vc.add_proof(proof);
        vc
    }
}
