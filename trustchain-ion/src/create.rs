use crate::attestor::{AttestorData, IONAttestor};
use crate::controller::{ControllerData, IONController};
use did_ion::sidetree::DIDStatePatch;
use did_ion::sidetree::{DocumentState, PublicKeyEntry, PublicKeyJwk};
use did_ion::sidetree::{Operation, Sidetree, SidetreeDID, SidetreeOperation};
use did_ion::ION;
use serde_json::to_string_pretty as to_json;
use ssi::jwk::JWK;
use ssi::one_or_many::OneOrMany;
use std::convert::TryFrom;
use std::io::Read;
use trustchain_core::utils::{generate_key, get_operations_path};

/// Returns a deserialized document state from a reader.
pub fn read_doc_state_from<T>(reader: T) -> Result<DocumentState, Box<dyn std::error::Error>>
where
    T: Read,
{
    let doc_state: DocumentState = serde_json::from_reader(reader)?;
    Ok(doc_state)
}

/// Makes a new DID subject to be controlled with correspondong create operation written to file.
pub fn create_operation(
    document_state: Option<DocumentState>,
    verbose: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Generate random keys
    let update_key = generate_key();
    let recovery_key = generate_key();
    ION::validate_key(&update_key).unwrap();
    ION::validate_key(&recovery_key).unwrap();
    let update_pk = PublicKeyJwk::try_from(update_key.to_public()).unwrap();
    let recovery_pk = PublicKeyJwk::try_from(recovery_key.to_public()).unwrap();

    // Create operation: Make the create patch from scratch or passed file
    let (document_state, generated_signing_key) = if let Some(mut document_state) = document_state {
        // If no keys loaded, generate a key
        let generated_signing_key: Option<JWK> = if document_state.public_keys.is_none() {
            let generated_signing_key = Some(generate_key());
            let public_key_entry = PublicKeyEntry::try_from(generated_signing_key.clone().unwrap());
            document_state.public_keys = Some(vec![public_key_entry.unwrap()]);
            generated_signing_key
        } else {
            None
        };
        (document_state, generated_signing_key)
    } else {
        // If no document passed, generate key and empty document
        let generated_signing_key = Some(generate_key());
        let public_key_entry = PublicKeyEntry::try_from(generated_signing_key.clone().unwrap());
        (
            DocumentState {
                public_keys: Some(vec![public_key_entry.unwrap()]),
                services: None,
            },
            generated_signing_key,
        )
    };

    let patches = vec![DIDStatePatch::Replace {
        document: document_state,
    }];

    // Make the create operation from patches
    let operation = ION::create_existing(&update_pk, &recovery_pk, patches).unwrap();

    // Verify operation
    let partially_verified_create_operation = operation.clone().partial_verify::<ION>();
    if verbose {
        println!(
            "Partially verified create: {}",
            partially_verified_create_operation.is_ok()
        );
    }

    let create_operation = match operation.clone() {
        Operation::Create(x) => Some(x),
        _ => None,
    };

    if verbose {
        println!("Create operation:");
        println!("{}", to_json(&create_operation).unwrap());
    }

    // Get DID information
    let controlled_did_suffix =
        ION::serialize_suffix_data(&create_operation.clone().unwrap().suffix_data)
            .unwrap()
            .to_string();
    let controlled_did_long = SidetreeDID::<ION>::from_create_operation(&create_operation.unwrap())
        .unwrap()
        .to_string();
    let controlled_did = controlled_did_long.rsplit_once(':').unwrap().0;
    if verbose {
        println!("Controlled DID suffix: {:?}", controlled_did_suffix);
        println!("Controlled DID (short-form): {:?}", controlled_did);
        println!("Controlled DID (long-form) : {:?}", controlled_did_long);
    }

    // If a signing key has been generated, IONAttestor needs to be saved
    if let Some(signing_key) = generated_signing_key {
        IONAttestor::try_from(AttestorData::new(
            controlled_did.to_string(),
            OneOrMany::One(signing_key),
        ))?;
    }

    // Write controller data: DID is arbitrarily set to contolled_did in creation
    IONController::try_from(ControllerData::new(
        controlled_did.to_string(),
        controlled_did.to_string(),
        update_key,
        recovery_key,
    ))?;

    // Write create operation to push to ION server
    let path = get_operations_path()?;
    std::fs::write(
        path.join(format!("create_operation_{}.json", controlled_did_suffix)),
        to_json(&operation).unwrap(),
    )?;

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use glob::glob;
    use trustchain_core::utils::init;

    // Test document state for making a create operation from
    const TEST_DOC_STATE: &str = r##"{
        "publicKeys": [
        {
            "id": "Mz94EfSCueClM5qv62SXxtLWRj4Ti7rR2wLWmW37aCs",
            "type": "JsonWebSignature2020",
            "publicKeyJwk": {
            "crv": "secp256k1",
            "kty": "EC",
            "x": "7VKmPezI_VEnMjOPfAeUnpQxhS1sLjAKfd0s7xrmx9A",
            "y": "gWZ5Bo197eZuMh3Se-3rqWCQjZWbuDpOYAaw8yC-yaQ"
            },
            "purposes": [
            "assertionMethod",
            "authentication",
            "keyAgreement",
            "capabilityInvocation",
            "capabilityDelegation"
            ]
        }
        ],
        "services": [
        {
            "id": "trustchain-controller-proof",
            "type": "TrustchainProofService",
            "serviceEndpoint": {
            "controller": "did:ion:test:EiA8yZGuDKbcnmPRs9ywaCsoE2FT9HMuyD9WmOiQasxBBg",
            "proofValue": "dummy_string"
            }
        }
        ]
    }"##;

    #[test]
    fn test_main_create() -> Result<(), Box<dyn std::error::Error>> {
        init();

        // 1. Run create with no document state passed
        create_operation(None, false)?;

        // 2. Run create with a document state passed
        let doc_state = read_doc_state_from(TEST_DOC_STATE.as_bytes())?;
        create_operation(Some(doc_state), false)?;

        // Try to read outputted create operations and  check they deserialize
        let path = get_operations_path()?;
        let pattern = path.join("create_operation_*.json");
        let pattern = pattern.into_os_string().into_string().unwrap();
        let paths = glob(pattern.as_str())?;

        let mut operation_count = 0;
        for path in paths {
            if let Ok(path_buf) = path {
                let operation_string = std::fs::read_to_string(path_buf)?;
                let _operation: Operation = serde_json::from_str(&operation_string)?;
                operation_count += 1;
            } else {
                panic!("No path present.");
            }
        }
        // Check two create operations exist.
        assert!(operation_count == 2);
        Ok(())
    }
}
