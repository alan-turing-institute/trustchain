use serde_json::to_string_pretty;
use ssi::ldp::now_ms;
use std::convert::TryFrom;
use trustchain_core::attestor::CredentialAttestor;
use trustchain_ion::attestor::IONAttestor;
use trustchain_ion::get_ion_resolver;

use ssi::vc::{Credential, LinkedDataProofOptions, VCDateTime};

// Linked @context provides a set of allowed fields for the
// credentail
// Provides detail "credentailSubject"
// "https://www.w3.org/2018/credentials/examples/v1"
// Provides image field "credentailSubject"
// "https://w3id.org/citizenship/v1"

// Other examples: https://www.w3.org/TR/vc-use-cases/
const TEST_UNSIGNED_VC: &str = r##"{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/v1",
    "https://w3id.org/citizenship/v1"
  ],
  "credentialSchema": {
    "id": "did:example:cdf:35LB7w9ueWbagPL94T9bMLtyXDj9pX5o",
    "type": "did:example:schema:22KpkXgecryx9k7N6XN1QoN3gXwBkSU8SfyyYQG"
  },
  "type": ["VerifiableCredential"],
  "issuer": "did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q",
  "image": "some_base64_representation",
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

#[ignore = "requires a running Sidetree node listening on http://localhost:3000"]
#[test]
fn test_attest_credential() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Set-up
    let did = "EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q";

    // Make resolver
    let resolver = get_ion_resolver("http://localhost:3000/");

    // 2. Load Attestor
    let attestor = IONAttestor::new(did);

    // 3. Read credential
    let vc: Credential = serde_json::from_str(TEST_UNSIGNED_VC)?;

    // 4. Perform proof add and verify
    resolver.runtime.block_on(async {
        let _ldp_opts = LinkedDataProofOptions {
            // The type of signature to be used can be specified.
            // The signing key is used to determine the signature type.
            // type_: Some("JsonWebSignature2020".to_string()),
            // type_: Some("EcdsaSecp256k1Signature2019".to_string()),
            ..LinkedDataProofOptions::default()
        };

        // Set issuer to "None" to prevent check for resolved key match
        // If it is the did, the resolver looks to match the pk to the
        // signing key provided
        // vc.issuer = None;

        // Generate proof:
        // If the context does not have all fields it will fail
        // as the JSONLD using Policy::Strict (when calling `sign_proof` and
        // https://docs.rs/ssi/0.4.0/ssi/ldp/trait.LinkedDataDocument.html#tymethod.to_dataset_for_signing)
        // Err(JSONLD(KeyExpansionFailed))
        //
        // The specific fn is in ssi::jsonld.rs
        //   expand_json(..., lax=false, ...) -> fails (strict JSON-LD)
        //   expand_json(..., lax=true, ...) -> passes (relaxed JSON-LD)
        //
        // The matched `@context` is necessary to parse successfully when strict.

        // Generate a proof
        // let proof = vc.generate_proof(&signing_key, &ldp_opts, &resolver).await;

        // Add proof to credential
        // vc.add_proof(proof.unwrap());

        // Use attest_credential method instead of generating and adding proof
        let vc_with_proof = attestor
            .attest_credential(&vc, None, &resolver)
            .await
            .unwrap();

        // Print VC with proof
        println!("{}", &to_string_pretty(&vc_with_proof).unwrap());

        // Verify
        let verification_result = vc_with_proof.verify(None, &resolver).await;

        // Print verification result
        println!(
            "---\n> Verification (no modification):\n{}",
            &to_string_pretty(&verification_result).unwrap()
        );

        assert!(verification_result.warnings.is_empty());
        assert!(verification_result.errors.is_empty());

        let mut vc_with_proof = vc_with_proof;
        // Change credential to make signature invalid
        vc_with_proof.expiration_date = Some(VCDateTime::try_from(now_ms()).unwrap());

        // Verify
        let verification_result = vc_with_proof.verify(None, &resolver).await;

        // Print verification result
        println!(
            "---\n> Verification (after modification):\n{}",
            &to_string_pretty(&verification_result).unwrap()
        );

        // No warnings but signature errror
        assert!(verification_result.warnings.is_empty());
        assert!(!verification_result.errors.is_empty());
    });

    Ok(())
}