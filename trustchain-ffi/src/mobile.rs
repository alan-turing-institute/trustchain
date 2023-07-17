use anyhow::{anyhow, Result};
use serde_json::to_string_pretty;
use ssi::{
    one_or_many::OneOrMany,
    vc::{Credential, LinkedDataProofOptions, Proof},
};
use tokio::runtime::Runtime;
use trustchain_api::{
    api::{TrustchainDIDAPI, TrustchainVCAPI},
    TrustchainAPI,
};
use trustchain_core::{
    chain::{Chain, DIDChain},
    config::core_config,
    verifier::Verifier,
};
use trustchain_ion::{get_ion_resolver, verifier::IONVerifier};

use crate::options::{EndpointOptions, ProofOptions};

/// Android localhost endpoint.
const ANDROID_ENDPOINT: &str = "http://10.0.2.2:3000/";

/// Example greet function.
pub fn greet() -> String {
    "Hello from Rust! 🦀".into()
}

/// Resolves a given DID document assuming trust in endpoint.
pub fn did_resolve(did: String, endpoint_opts: String) -> Result<String> {
    let endpoint_options: EndpointOptions = serde_json::from_str(&endpoint_opts)?;
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        TrustchainAPI::resolve(&did, endpoint_options.resolver_endpoint.to_address())
            .await
            .map_err(|e| anyhow!(e))
            .and_then(|(_, doc, _)| serde_json::to_string_pretty(&doc).map_err(|e| anyhow!(e)))
    })
}
/// Verifies a given DID assuming trust in endpoint.
pub fn did_verify(did: String, endpoint_opts: String, proof_opts: String) -> Result<()> {
    let endpoint_options: EndpointOptions = serde_json::from_str(&endpoint_opts)?;
    let proof_options: ProofOptions = serde_json::from_str(&proof_opts)?;
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        let verifier = IONVerifier::with_endpoint(
            get_ion_resolver(&endpoint_options.resolver_endpoint.to_address()),
            endpoint_options.bundle_endpoint.to_address(),
        );
        verifier
            .verify(&did, core_config().root_event_time)
            .await
            .map_err(|err| anyhow!(err.to_string()))?;
        Ok(())
    })
}

/// Verifies a verifiable credential. Analogous with [didkit](https://docs.rs/didkit/latest/didkit/c/fn.didkit_vc_verify_credential.html).
pub fn vc_verify_credential(
    credential: String,
    endpoint_opts: String,
    proof_opts: String,
) -> Result<String> {
    let endpoint_options: EndpointOptions = serde_json::from_str(&endpoint_opts)?;
    let proof_options: ProofOptions = serde_json::from_str(&proof_opts)?;
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        let credential: Credential = serde_json::from_str(&credential)?;
        let verifier = IONVerifier::with_endpoint(
            get_ion_resolver(&endpoint_options.resolver_endpoint.to_address()),
            endpoint_options.bundle_endpoint.to_address(),
        );
        let signature_only = proof_options.signature_only;
        let root_event_time = proof_options.root_event_time;

        // NB. When using android emulator, the time is less than the created time on
        // the credential. This leads to a failure upon the proofs being checked:
        // https://docs.rs/ssi/0.4.0/src/ssi/vc.rs.html#1243 (filtered here)
        // https://docs.rs/ssi/0.4.0/src/ssi/vc.rs.html#1973-1975 (created time checked here)
        //
        // A workaround is to set the "created" time from the credential directly with
        // LinkedDataProofOptions
        let ldpo = match credential.proof {
            Some(OneOrMany::One(Proof {
                created: created_time,
                ..
            })) => LinkedDataProofOptions {
                created: created_time,
                ..Default::default()
            },
            _ => return Err(anyhow!("No proof or created time available in proof.")),
        };
        // TODO: try setting time as now from emulator to check time used from now_ms() call
        // Verify credential signature with LinkedDataProofOptions
        let verification_result = credential.verify(Some(ldpo), verifier.resolver()).await;

        // Get DID chain if not signature only
        let did_chain = if signature_only {
            None
        } else {
            let issuer = match credential.issuer {
                Some(issuer) => issuer.get_id(),
                _ => return Err(anyhow!("No issuer present in credential.")),
            };
            Some(verifier.verify(&issuer, root_event_time).await)
        };

        // Returns
        if !verification_result.errors.is_empty() {
            Err(anyhow!(
                "Invalid signature:\n{}",
                serde_json::to_string_pretty(&verification_result.errors).unwrap()
            ))
        } else if signature_only {
            Ok("OK: signature only".to_string())
        } else if let Some(did_chain) = did_chain {
            match did_chain {
                Ok(_) => Ok("OK".to_string()),
                Err(e) => Err(anyhow!(e.to_string())),
            }
        } else {
            Err(anyhow!("No DID chain returned, failed to verify issuer."))
        }
    })
}
/// Issues a verifiable presentation. Analogous with [didkit](https://docs.rs/didkit/latest/didkit/c/fn.didkit_vc_issue_presentation.html).
pub fn vc_issue_presentation(
    presentation_json: String,
    proof_options_json: String,
    key_json: String,
) {
    todo!()
}
/// Verifies a verifiable presentation. Analogous with [didkit](https://docs.rs/didkit/latest/didkit/c/fn.didkit_vc_verify_presentation.html).
pub fn vc_verify_presentation(
    presentation_json: String,
    proof_options_json: String,
) -> Result<String> {
    todo!()
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_did_resolve() {}

    #[test]
    fn test_did_verify() {}

    #[test]
    fn test_vc_verify_credential() {}

    #[test]
    fn test_vc_issue_presentation() {}

    #[test]
    fn test_vc_verify_presentation() {}
}
