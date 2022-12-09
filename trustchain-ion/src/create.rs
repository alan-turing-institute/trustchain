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
use trustchain_core::utils::{generate_key, get_operations_path};

/// Makes a new DID subject to be controlled with correspondong create operation written to file.
pub fn create_operation(
    file_path: Option<&String>,
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
    let (document_state, signing_key) = if let Some(file_path_data) = file_path {
        // Load document from file if passed
        let contents = std::fs::read_to_string(file_path_data)
            .expect("Should have been able to read the file");
        let mut loaded_document_state: DocumentState = serde_json::from_str(&contents).unwrap();

        // If no keys loaded, generate a key
        let signing_key: Option<JWK> = if loaded_document_state.public_keys.is_none() {
            let signing_key = Some(generate_key());
            let public_key_entry = PublicKeyEntry::try_from(signing_key.clone().unwrap());
            loaded_document_state.public_keys = Some(vec![public_key_entry.unwrap()]);
            signing_key
        } else {
            None
        };
        (loaded_document_state, signing_key)
    } else {
        // If no document passed, generate key
        let signing_key = Some(generate_key());
        let public_key_entry = PublicKeyEntry::try_from(signing_key.clone().unwrap());
        (
            DocumentState {
                public_keys: Some(vec![public_key_entry.unwrap()]),
                services: None,
            },
            signing_key,
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

    // If a signing key has been made, IONAttestor needs to be saved
    if let Some(signing_key) = signing_key {
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

    #[test]
    fn test_main_create() -> Result<(), Box<dyn std::error::Error>> {
        init();
        // Run create
        create_operation(None, false)?;

        // Try to read outputted create operation
        let path = get_operations_path()?;
        let pattern = path.join("create_operation_*.json");
        let pattern = pattern.into_os_string().into_string().unwrap();
        let paths = glob(pattern.as_str())?;
        for (i, path) in paths.enumerate() {
            if let Ok(path_buf) = path {
                let operation_string = std::fs::read_to_string(path_buf)?;
                let _operation: Operation = serde_json::from_str(&operation_string)?;
                assert!(i < 1);
            } else {
                panic!("No path present.");
            }
        }
        Ok(())
    }
}
