use did_ion::{sidetree::SidetreeClient, ION};
use ssi::did::{VerificationMethod, VerificationMethodMap};
use ssi::one_or_many::OneOrMany;
use trustchain_core::resolver::{DIDMethodWrapper, Resolver};

// Type aliases
pub type IONResolver = Resolver<DIDMethodWrapper<SidetreeClient<ION>>>;

pub fn test_resolver(endpoint: &str) -> IONResolver {
    IONResolver::from(SidetreeClient::<ION>::new(Some(String::from(endpoint))))
}

use did_ion::sidetree::Sidetree;
use ssi::did_resolve::Metadata;
use ssi::jwk::JWK;
use std::convert::TryFrom;
use trustchain_core::data::{TEST_RECOVERY_KEY, TEST_UPDATE_KEY};
use trustchain_core::key_manager::KeyManager;
use trustchain_ion::controller::ControllerData;
use trustchain_ion::controller::IONController;

// Make a IONController using this test function
fn test_controller(
    did: &str,
    controlled_did: &str,
) -> Result<IONController, Box<dyn std::error::Error>> {
    let update_key: JWK = serde_json::from_str(TEST_UPDATE_KEY)?;
    let recovery_key: JWK = serde_json::from_str(TEST_RECOVERY_KEY)?;
    IONController::try_from(ControllerData::new(
        did.to_string(),
        controlled_did.to_string(),
        update_key,
        recovery_key,
    ))
}

use std::fs::File;
use trustchain_core::key_manager::KeyManagerError;
use trustchain_ion::KeyUtils;

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

fn verify(did: &str, controlled_did: &str) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Set-up
    // Load keys from shared path
    let home = std::env::var("HOME")?;
    let signing_key_file = format!("{}/.trustchain/key_manager/{}/signing_key.json", home, did);
    let update_key_file = format!(
        "{}/.trustchain/key_manager/{}/update_key.json",
        home, controlled_did
    );
    let recovery_key_file = format!(
        "{}/.trustchain/key_manager/{}/recovery_key.json",
        home, controlled_did
    );
    let signing_key = read_from_specific_file(&signing_key_file)?;
    let update_key = read_from_specific_file(&update_key_file)?;
    let recovery_key = read_from_specific_file(&recovery_key_file)?;

    // Unwrap the keys
    let (signing_key, _, _) = if let (
        OneOrMany::One(signing_key_val),
        OneOrMany::One(update_key_val),
        OneOrMany::One(recovery_key_val),
    ) = (signing_key, update_key, recovery_key)
    {
        (signing_key_val, update_key_val, recovery_key_val)
    } else {
        panic!()
    };

    // 2. Resolve controlled_did: doc, doc_meta
    // Construct a Trustchain Resolver from a Sidetree (ION) DIDMethod.
    let resolver = test_resolver("http://localhost:3000/");

    // Resolve DID Document & Metadata.
    let full_controlled_did = format!("did:ion:test:{}", &controlled_did);
    let result = resolver.resolve_as_result(&full_controlled_did);

    // Check the result is not an error.
    // If this fails, make sure the Sidetree server is up and listening on the above URL endpoint.
    assert!(result.is_ok());

    // Destructure
    let (_res_meta, doc, doc_meta) = if let (_res_meta, doc, Some(doc_meta)) = result.unwrap() {
        (_res_meta, doc, doc_meta)
    } else {
        panic!()
    };

    // Get controller and proof
    let (expected_proof_value, controller_str) =
        if let Some(property_set) = doc_meta.property_set.as_ref() {
            if let Some(Metadata::Map(proof)) = property_set.get("proof") {
                if let (Some(Metadata::String(proof_value)), Some(Metadata::String(controller))) =
                    (proof.get("proofValue"), proof.get("id"))
                {
                    (proof_value.to_string(), controller.to_string())
                } else {
                    panic!()
                }
            } else {
                panic!()
            }
        } else {
            panic!()
        };

    // Check the DID Document was successfully resolved.
    assert!(doc.is_some());

    // 3. Decode proof: get payload, check payload is hash of doc
    let doc = doc.unwrap();
    let doc_canon = ION::json_canonicalization_scheme(&doc)?;
    let doc_canon_hash = ION::hash(doc_canon.as_bytes());

    // 3.1 Get public key from controller DID
    let (_, controller_doc, _) = match resolver.resolve_as_result(&controller_str) {
        Ok((res_meta, Some(controller_doc), Some(controller_doc_meta))) => {
            (res_meta, controller_doc, controller_doc_meta)
        }
        _ => panic!(),
    };

    // 3.2 Extract signing key
    let signing_public_key =
        if let Some(verfication_method) = controller_doc.verification_method.as_ref() {
            if let VerificationMethod::Map(VerificationMethodMap {
                public_key_jwk: Some(val),
                ..
            }) = verfication_method.first().unwrap()
            {
                val
            } else {
                panic!()
            }
        } else {
            panic!()
        };

    assert_eq!(&signing_key.to_public(), signing_public_key);

    // 4. Check signature on proof_value is valid for signing key
    //      AND
    //    that decoded payload is equal to reconstructed hashed document
    let decoded_result: String =
        ssi::jwt::decode_verify(&expected_proof_value, signing_public_key)?;

    // Assert decoded_result is equal to reconstructed hash doc_canon_hash
    assert_eq!(decoded_result, doc_canon_hash);

    Ok(())
}

#[test]
#[ignore]
fn trustchain_attest() -> Result<(), Box<dyn std::error::Error>> {
    // root and root-plus-1
    verify(
        "EiCClfEdkTv_aM3UnBBhlOV89LlGhpQAbfeZLFdFxVFkEg",
        "EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A",
    )?;

    // root-plus-1 and root-plus-2
    verify(
        "EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A",
        "EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q",
    )?;

    Ok(())
}
