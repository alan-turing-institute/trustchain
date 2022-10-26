use did_ion::sidetree::Sidetree;
use did_ion::ION;
use serde_json::to_string_pretty;
use ssi::did::{VerificationMethod, VerificationMethodMap};
use ssi::did_resolve::Metadata;
use ssi::jwk::JWK;
use ssi::jws::detached_verify;
use ssi::one_or_many::OneOrMany;
use std::fs::File;
use trustchain_core::attestor::Attestor;
use trustchain_core::key_manager::KeyManager;
use trustchain_core::key_manager::KeyManagerError;
use trustchain_core::utils::canonicalize;
use trustchain_ion::attestor::IONAttestor;
use trustchain_ion::test_resolver;
use trustchain_ion::KeyUtils;

use ssi::vc::{Credential, Proof};

// Mixture of EXAMPLE 24 and 34: https://www.w3.org/TR/vc-data-model/#dfn-verifiable-credentials
const TEST_UNSIGNED_VC: &str = r##"{
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://www.w3.org/2018/credentials/examples/v1"
    ],
    "type": ["VerifiableCredential", "UniversityDegreeCredential"],
    "credentialSchema": {
      "id": "did:example:cdf:35LB7w9ueWbagPL94T9bMLtyXDj9pX5o",
      "type": "did:example:schema:22KpkXgecryx9k7N6XN1QoN3gXwBkSU8SfyyYQG"
    },
    "issuer": "did:example:Wz4eUg7SetGfaUVCn8U9d62oDYrUJLuUtcy619",
    "credentialSubject": {
      "givenName": "Jane",
      "familyName": "Doe",
      "image": "some_base64_image",
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

#[test]
fn sign_vc() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Set-up
    let did = "EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A";

    // Load keys from shared path
    // let home = std::env::var("HOME")?;
    // let signing_key_file = format!("{}/.trustchain/key_manager/{}/signing_key.json", home, did);
    // let signing_key = read_from_specific_file(signing_key_file);

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
    let signing_pk = attestor.signing_pk(None)?;

    // Check the signature is valid by passing in the payload and detached signature
    let det_ver = detached_verify(
        &proof,
        ION::hash(vc_canon.as_bytes()).as_bytes(),
        &signing_pk,
    );
    assert!(det_ver.is_ok());

    Ok(())
}
