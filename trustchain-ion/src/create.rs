use crate::attestor::{AttestorData, IONAttestor};
use crate::controller::{ControllerData, IONController};
use crate::{KeyUtils, KEY_UTILS};
use did_ion::sidetree::DIDStatePatch;
use did_ion::sidetree::{DocumentState, PublicKeyEntry, PublicKeyJwk};
use did_ion::sidetree::{Operation, Sidetree, SidetreeDID, SidetreeOperation};
use did_ion::ION;
use serde_json::to_string_pretty as to_json;
use ssi::jwk::JWK;
use ssi::one_or_many::OneOrMany;
use std::convert::TryFrom;
use trustchain_core::key_manager::KeyManager;
use trustchain_core::utils::get_operations_path;

// Binary to make a new DID subject to be controlled and correspondong create operation.
pub fn main_create(
    file_path: Option<&String>,
    verbose: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Make keys for controlled DID
    //
    // 1.0 Generate random keys
    let update_key = KEY_UTILS.generate_key();
    let recovery_key = KEY_UTILS.generate_key();

    // 1.1 Validate keys
    ION::validate_key(&update_key).unwrap();
    ION::validate_key(&recovery_key).unwrap();

    // 1.2 Get PublicKeyJwk versions
    let update_pk = PublicKeyJwk::try_from(update_key.to_public()).unwrap();
    let recovery_pk = PublicKeyJwk::try_from(recovery_key.to_public()).unwrap();

    // 1.3 Signing key: optional variable to assign to if private signing key made for DID
    // Typically only a self-controller will do this when they want to make themselves a subject at the same time as creating a DID to control
    let mut signing_key: Option<JWK> = None;

    // 2. Create operation
    // 2.1 Make the create patch from scratch or passed file
    let document_state: DocumentState = if let Some(file_path_data) = file_path {
        // 1. Load document from file if passed
        let contents = std::fs::read_to_string(file_path_data)
            .expect("Should have been able to read the file");

        // Contents are a DocumentState
        let mut loaded_document_state: DocumentState = serde_json::from_str(&contents).unwrap();
        // If no keys loaded
        if loaded_document_state.public_keys.is_none() {
            signing_key = Some(KeyUtils.generate_key());
            let public_key_entry = PublicKeyEntry::try_from(signing_key.clone().unwrap());
            loaded_document_state.public_keys = Some(vec![public_key_entry.unwrap()]);
        }
        loaded_document_state
    } else {
        // If no document passed, generate key
        signing_key = Some(KeyUtils.generate_key());
        let public_key_entry = PublicKeyEntry::try_from(signing_key.clone().unwrap());
        // TODO
        DocumentState {
            public_keys: Some(vec![public_key_entry.unwrap()]),
            services: None,
        }
    };

    // 2.2 Make vec of patches from document state
    let patches = vec![DIDStatePatch::Replace {
        document: document_state,
    }];

    // 2.3  Make the create operation from pathces
    let operation = ION::create_existing(&update_pk, &recovery_pk, patches).unwrap();

    // 2.4 Verify the operation enum
    let partially_verified_create_operation = operation.clone().partial_verify::<ION>();
    if verbose {
        println!(
            "Partially verified create: {}",
            partially_verified_create_operation.is_ok()
        );
    }

    // 2.5 Get the data of the operation enum
    let create_operation = match operation.clone() {
        Operation::Create(x) => Some(x),
        _ => None,
    };

    // 2.6 Print JSON operation
    if verbose {
        println!("Create operation:");
        println!("{}", to_json(&create_operation).unwrap());
    }

    // 3. Get DID information
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

    // 4. Write to file
    // 4.1 If a signing key has been made, IONAttestor needs to be saved
    if let Some(signing_key) = signing_key {
        IONAttestor::try_from(AttestorData::new(
            controlled_did.to_string(),
            OneOrMany::One(signing_key),
        ))?;
    }

    // 4.2 Write controller data: did is arbitrarily set to contolled_did in creation
    IONController::try_from(ControllerData::new(
        controlled_did.to_string(),
        controlled_did.to_string(),
        update_key,
        recovery_key,
    ))?;

    // 4.2 Write create operation to push to ION server
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
        main_create(None, false)?;

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
