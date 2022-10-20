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
#[ignore]
fn trustchain_attest() -> Result<(), Box<dyn std::error::Error>> {
    init();

    // 1. Set-up
    // Set controlled_did
    let controlled_did = "EiDAQdupXXEwqO6d5Oh9camtm8Sv-3-viA4luy0uClNmWA";

    // Set did
    let did = "EiBP_RYTKG2trW1_SN-e26Uo94I70a8wB4ETdHy48mFfMQ";

    // Write keys as &str
    let home = std::env::var("HOME")?;
    let signing_key_file = format!(
        "{}/.trustchain/tests/key_manager/{}/signing_key.json",
        home, did
    );
    let update_key_file = format!(
        "{}/.trustchain/tests/key_manager/{}/update_key.json",
        home, controlled_did
    );
    let recovery_key_file = format!(
        "{}/.trustchain/tests/key_manager/{}/recovery_key.json",
        home, controlled_did
    );
    println!("{:?}", signing_key_file);
    let signing_key = read_from_specific_file(&signing_key_file)?;
    let update_key = read_from_specific_file(&update_key_file)?;
    let recovery_key = read_from_specific_file(&recovery_key_file)?;

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
    let expected_proof_value = "eyJhbGciOiJFUzI1NksifQ.IkVpQjdMOWJZeU5MMjBsbEptY25jbzk4TFliZzlDbWJSVU4xV3NHSXJhVzBvTkEi.TiSMTT9KRDi879EBo0QsLDz4H_LI4FJ9q1i2FHhGquMywgVlTVSnn4uqaQkBuPERtpl9YgmSjSUi0Vc5v3jarg";

    // TODO: once attestation is made, extract proof value from doc_meta instead
    // of passing as value

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

    // 3. Decode proof: get payload, check payload is hash of doc
    let doc = doc.unwrap();
    let doc_canon = ION::json_canonicalization_scheme(&doc)?;
    let doc_canon_hash = ION::hash(doc_canon.as_bytes());

    // 4. Check signature on proof_value is valid for signing key
    //    AND
    //    that decoded payload is equal to reconstructed hashed document
    let decoded_result: String = ssi::jwt::decode_verify(expected_proof_value, &signing_key)?;
    assert_eq!(decoded_result, doc_canon_hash);

    Ok(())
}
