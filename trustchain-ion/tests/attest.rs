use ssi::one_or_many::OneOrMany;

use did_ion::{sidetree::SidetreeClient, ION};
use trustchain_core::attestor::{Attestor, AttestorError};
use trustchain_core::controller::Controller;
use trustchain_core::resolver::{DIDMethodWrapper, Resolver};

// Type aliases
pub type IONResolver = Resolver<DIDMethodWrapper<SidetreeClient<ION>>>;

pub fn test_resolver(endpoint: &str) -> IONResolver {
    IONResolver::from(SidetreeClient::<ION>::new(Some(String::from(endpoint))))
}
use mockall::mock;
use ssi::jwk::Params;
use ssi::jwt;
use std::fmt::format;
use std::io::Read;
use std::path::Path;
use std::sync::Once;

use trustchain_core::TRUSTCHAIN_DATA;

use did_ion::sidetree::Sidetree;
use serde_json;
use ssi::did_resolve::DocumentMetadata;
use ssi::jwk::JWK;
use std::convert::TryFrom;
use trustchain_core::data::{TEST_RECOVERY_KEY, TEST_UPDATE_KEY};
use trustchain_core::data::{TEST_SIDETREE_DOCUMENT_METADATA, TEST_TRUSTCHAIN_DOCUMENT_METADATA};
use trustchain_core::init;
use trustchain_core::key_manager::KeyManager;
use trustchain_ion::attestor::IONAttestor;
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

#[test]
fn trustchain_attest() -> Result<(), Box<dyn std::error::Error>> {
    init();

    // 1. Set-up

    // Write keys as &str
    let home = std::env::var("$USER")?;
    let signing_key_file = format!("{}/.trustchain/key_manager/EiAVrUJpqDgrvwr4xfwAUj_o9l5RZlzlgu7VGTY93UzpyQ/signing_key.json", home);
    let update_key_file = format!(
        "{}/.trustchain/key_manager/EiCQt8FvI6ClKUU6fpqm0q2hDNNPhS5WmhsswKxgOMAvgA/update_key.json",
        home
    );
    let recovery_key_file = format!("{}/.trustchain/key_manager/EiCQt8FvI6ClKUU6fpqm0q2hDNNPhS5WmhsswKxgOMAvgA/recovery_key.json", home);
    let signing_key = read_from_specific_file(&signing_key_file)?;
    let update_key = read_from_specific_file(&update_key_file)?;
    let recovery_key = read_from_specific_file(&recovery_key_file)?;
    // println!("-------integration test attestor---------------");
    // println!("{:?}", signing_key);
    // println!("-------");

    // Unwrap the keys
    let (signing_key, update_key, recovery_key) = if let (
        OneOrMany::One(signing_key_val),
        OneOrMany::One(update_key_val),
        OneOrMany::One(recovery_key_val),
    ) = (signing_key, update_key, recovery_key)
    {
        (signing_key_val, update_key_val, recovery_key_val)
    } else {
        panic!()
    };

    // Set controlled_did
    let controlled_did = "EiCQt8FvI6ClKUU6fpqm0q2hDNNPhS5WmhsswKxgOMAvgA";

    // Set did
    let did = "EiAVrUJpqDgrvwr4xfwAUj_o9l5RZlzlgu7VGTY93UzpyQ";

    // Save keys to did and controlled_did
    let controller = IONController::try_from(ControllerData::new(
        did.to_string(),
        controlled_did.to_string(),
        update_key,
        recovery_key,
    ));

    // Save signing key
    let attestor = IONAttestor::try_from((did.to_string(), OneOrMany::One(signing_key.clone())));

    // Set proof_value as hardcoded one to check
    let expected_proof_value = "eyJhbGciOiJFUzI1NksifQ.IkVpQ1pJNDRQYU9JQV9KaVE1NDZpMjQ4RVF3Y05fQXZVWjJQNG1memJ1eGNkRFEi.N8hYOEEtn1D6oqI6MLSFk8keJYDosxU59XD_xkyk974bdzWRTgHRe_H4KfGAJ9f9RDOB9gdMZkPlbY2fPbKtOg";

    // 2. Resolve controlled_did: doc, doc_meta

    // Construct a Trustchain Resolver from a Sidetree (ION) DIDMethod.
    let resolver = test_resolver("http://localhost:3000/");

    // Resolve DID Document & Metadata.
    let full_controlled_did = format!("did:ion:test:{}", &controlled_did);
    let result = resolver.resolve_as_result(&full_controlled_did);

    // Check the result is not an error.
    // If this fails, make sure the Sidetree server is up and listening on the above URL endpoint.
    assert!(result.is_ok());

    let (_res_meta, doc, doc_meta) = result.unwrap();

    // Check the DID Document was successfully resolved.
    assert!(doc.is_some());
    let doc = doc.unwrap();

    // 3. Decode proof: get payload, check payload is hash of doc

    let algorithm = ION::SIGNATURE_ALGORITHM;

    let canonical_document = match ION::json_canonicalization_scheme(&doc) {
        Ok(str) => str,
        Err(_) => {
            return Err(Box::new(AttestorError::InvalidDocumentParameters(
                doc.id.clone(),
            )))
        }
    };

    // TODO: check we really want this to be the proof?
    let proof = (&doc.id.clone(), canonical_document);

    let proof_json = match ION::json_canonicalization_scheme(&proof) {
        Ok(str) => str,
        Err(_) => {
            return Err(Box::new(AttestorError::InvalidDocumentParameters(
                doc.id.clone(),
            )))
        }
    };
    let proof_json_bytes = ION::hash(proof_json.as_bytes());
    let proof_json_str = proof_json_bytes.as_str();

    let decoded_proof_value: String = ssi::jwt::decode_unverified(&expected_proof_value)?;

    println!("{:?}", decoded_proof_value);
    println!("{:?}", proof_json_str);

    // 4. Check signature on proof_value is valid for signing key
    //    AND
    //    that decoded payload is equal to reconstructed hashed document
    let decoded_result: String = ssi::jwt::decode_verify(&expected_proof_value, &signing_key)?;
    assert_eq!(decoded_result, proof_json_str);

    Ok(())
}
