use clap::{arg, command, Arg, ArgAction};
use ssi::did::{Document, Service, ServiceEndpoint};
use ssi::jwk::JWK;

use did_ion::sidetree::{DIDStatePatch, DIDSuffix};
use did_ion::sidetree::{DocumentState, PublicKeyEntry, PublicKeyJwk};
use did_ion::sidetree::{
    Operation, ServiceEndpointEntry, Sidetree, SidetreeDID, SidetreeOperation,
};
use did_ion::ION;
use serde_json::to_string_pretty as to_json;
use serde_json::{Map, Value};
use ssi::one_or_many::OneOrMany;
use std::convert::TryFrom;
use trustchain_core::key_manager::{KeyManager, KeyType};
use trustchain_ion::KeyUtils;

// use trustchain_core::key_manager::{generate_key, save_key, KeyType};

// fn template_doc_state() -> DocumentState {
//     // Make a signing
//     let signing_key = Some(generate_key());
//     let public_key_entry = PublicKeyEntry::try_from(signing_key.clone().unwrap());

//     // Make object for services endpoint
//     let mut obj: Map<String, Value> = Map::new();
//     obj.insert(
//         "controller".to_string(),
//         Value::from("did:ion:test:EiA8yZGuDKbcnmPRs9ywaCsoE2FT9HMuyD9WmOiQasxBBg".to_string()),
//     );
//     obj.insert(
//         "proofValue".to_string(),
//         Value::from("dummy_string".to_string()),
//     );
//     let test_service = vec![ServiceEndpointEntry {
//         id: "trustchain-controller-proof".to_string(),
//         r#type: "TrustchainProofService".to_string(),
//         service_endpoint: ServiceEndpoint::Map(serde_json::Value::Object(obj.clone())),
//     }];
//     DocumentState {
//         public_keys: Some(vec![public_key_entry.unwrap()]),
//         services: Some(test_service),
//     }
// }

// Binary to make a new DID subject to be controlled and correspondong create operation.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // CLI pass: verbose, did, controlled_did
    let matches = command!()
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .action(ArgAction::SetTrue),
        )
        .arg(arg!(-f --file_path <FILE_PATH>).required(false))
        .get_matches();

    let verbose = *matches.get_one::<bool>("verbose").unwrap();
    let file_path = matches.get_one::<String>("file_path");

    // 1. Make keys for controlled DID
    //
    // 1.0 Generate random keys
    let update_key = KeyUtils.generate_key();
    let recovery_key = KeyUtils.generate_key();

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

    // println!("_-------");
    // println!("{}", to_json(&template_doc_state()).unwrap());
    // println!("_-------");
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
    let did_short = ION::serialize_suffix_data(&create_operation.clone().unwrap().suffix_data)
        .unwrap()
        .to_string();
    let did_long = SidetreeDID::<ION>::from_create_operation(&create_operation.clone().unwrap())
        .unwrap()
        .to_string();
    if verbose {
        println!("DID suffix: {:?}", did_short);
        println!("Long: {:?}", did_long);
    }
    println!("{}", DIDSuffix(did_short.to_string()));
    // 4. Writing to file
    // 4.1 Writing keys
    // TODO: refactor to use a new method for controller:
    // TrustchainController::create(update_key, recovery_key, signing_key, did);
    KeyUtils.save_key(&did_short, KeyType::UpdateKey, &update_key, false)?;
    KeyUtils.save_key(&did_short, KeyType::RecoveryKey, &recovery_key, false)?;
    if signing_key.is_some() {
        KeyUtils.save_key(
            &did_short,
            KeyType::SigningKey,
            &signing_key.unwrap(),
            false,
        )?;
    }

    // 4.2 Write create operation to push to ION server
    // TODO: use publisher to push JSON directly to ION server
    // if use_publisher {
    // publisher.post(create_operation);
    // }
    std::fs::write(
        format!("create_operation_{}.json", did_short),
        to_json(&operation).unwrap(),
    )?;

    Ok(())
}
