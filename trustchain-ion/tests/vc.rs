use did_ion::sidetree::Sidetree;
use did_ion::ION;
use futures::executor::block_on;
use serde_json::{json, to_string_pretty};
use ssi::did::{Contexts, VerificationMethod, VerificationMethodMap};
use ssi::did_resolve::{DIDResolver, Metadata, ResolutionInputMetadata};
use ssi::jwk::{Algorithm, JWK};
use ssi::jws::detached_verify;
use ssi::ldp::{now_ms, JsonWebSignature2020, LinkedDataDocument, LinkedDataProofs};
use ssi::one_or_many::OneOrMany;
use std::convert::TryFrom;
use std::fs::File;
use std::thread::panicking;
use trustchain_core::attestor::Attestor;
use trustchain_core::key_manager::KeyManager;
use trustchain_core::key_manager::KeyManagerError;
use trustchain_core::utils::canonicalize;
use trustchain_ion::attestor::IONAttestor;
use trustchain_ion::test_resolver;
use trustchain_ion::KeyUtils;

use ssi::vc::{Credential, Issuer, LinkedDataProofOptions, Proof, VCDateTime, URI};

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

fn read_from_specific_file(path: &str) -> Result<OneOrMany<JWK>, KeyManagerError> {
    // Open the file
    let file = File::open(&path);

    // Read from the file and return
    if let Ok(file) = file {
        KeyUtils.read_keys_from(Box::new(file))
    } else {
        Err(KeyManagerError::FailedToLoadKey)
        // panic!();
    }
}

#[ignore = "requires a running Sidetree node listening on http://localhost:3000"]
#[test]
fn sign_vc() -> Result<(), Box<dyn std::error::Error>> {
    // Part 1: Use trustchain-proof-service process for signing and verifying credential
    // 1. Set-up
    let did = "EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q";

    // Load keys from shared path
    let home = std::env::var("HOME")?;
    let signing_key_file = format!("{}/.trustchain/key_manager/{}/signing_key.json", home, did);
    let signing_key = match read_from_specific_file(&signing_key_file) {
        Ok(OneOrMany::One(signing_key)) => signing_key,
        _ => panic!("Could not read signing key."),
    };
    // Add algorithm to key
    // signing_key.algorithm = Some(Algorithm::ES256K);

    // 2. Load Attestor
    let attestor = IONAttestor::new(did);

    // 3. Read credential
    let mut vc: Credential = serde_json::from_str(TEST_UNSIGNED_VC)?;

    // 4. Canonicalize and attest
    let vc_canon = canonicalize(&vc)?;

    // 5. Get a detached JWS signature for VC
    let proof = attestor.attest_jws(&vc_canon, None);
    assert!(proof.is_ok());

    // Unwrap attestation proof
    let proof = proof.unwrap();

    // 6. Set proof property
    vc.proof = Some(OneOrMany::One(Proof {
        jws: Some(proof.clone()),
        ..Default::default()
    }));

    // Print the VC with proof
    println!("{}", &to_string_pretty(&vc).unwrap());

    // 7. Verify
    let signing_pk = attestor.get_signing_key(None, true)?;

    // Check the signature is valid by passing in the payload and detached signature
    let det_ver = detached_verify(
        &proof,
        ION::hash(vc_canon.as_bytes()).as_bytes(),
        &signing_pk,
    );
    assert!(det_ver.is_ok());

    // Part 2: attempt to use the LDP for proofs and verification of credentials
    // Make resolver
    let resolver = test_resolver("http://localhost:3000/");

    // Get issuer DID from credential
    let did = match vc.issuer {
        Some(Issuer::URI(URI::String(ref did))) => did.clone(),
        _ => panic!(),
    };

    resolver.runtime.block_on(async {
        // Check resolver
        // let (res_meta, doc, doc_meta) =
        // resolver.resolve(&did.to_string(), &ResolutionInputMetadata::default()).await;
        // println!("{}", &to_string_pretty(&doc.unwrap()).unwrap());

        println!("{}", &to_string_pretty(&signing_key).unwrap());

        let ldp_opts = LinkedDataProofOptions {
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

        // Try to generate proof:
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
        let proof = vc.generate_proof(&signing_key, &ldp_opts, &resolver).await;

        // Add proof to credential
        vc.add_proof(proof.unwrap());

        // Print VC with proof
        println!("{}", &to_string_pretty(&vc).unwrap());

        // Verify
        let verification_result = vc.verify(None, &resolver).await;

        // Print verification result
        println!(
            "---\n> Verification (no modification):\n{}",
            &to_string_pretty(&verification_result).unwrap()
        );

        // Change doc to challenge proof
        vc.expiration_date = Some(VCDateTime::try_from(now_ms()).unwrap());

        // Verify
        let verification_result = vc.verify(None, &resolver).await;

        // Print verification result
        println!(
            "---\n> Verification (after modification):\n{}",
            &to_string_pretty(&verification_result).unwrap()
        );

        // TODO: make a new function in Attestor that takes a credential as an argument
        // and generates and adds proof
    });

    Ok(())
}
