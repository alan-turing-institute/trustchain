use clap::{arg, command, Arg, ArgAction};
use ssi::did::{Document, Service};
use ssi::jwk::JWK;

use did_ion::sidetree::DIDStatePatch;
use did_ion::sidetree::{DocumentState, PublicKeyEntry, PublicKeyJwk};
use did_ion::sidetree::{Operation, Sidetree, SidetreeDID, SidetreeOperation};
use did_ion::ION;

use serde_json::to_string_pretty as to_json;
use std::convert::TryFrom;

use trustchain_core::key_manager::{generate_key, save_key, KeyType};

// TODO: Implement a function to convert an SSI document (https://docs.rs/ssi/latest/ssi/did/struct.Document.html#)
// into a DocumentState (https://docs.rs/did-ion/0.1.0/did_ion/sidetree/struct.DocumentState.html)
fn document_as_document_state(doc: &Document) -> DocumentState {
    todo!()
}

// Binary to make a new DID subject to be controlled and correspondong create operation.
fn main() {
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
    let update_key = generate_key();
    let recovery_key = generate_key();

    // 1.1 Validate keys
    ION::validate_key(&update_key).unwrap();
    ION::validate_key(&recovery_key).unwrap();

    // 1.2 Get PublicKeyJwk versions
    let update_pk = PublicKeyJwk::try_from(update_key.to_public()).unwrap();
    let recovery_pk = PublicKeyJwk::try_from(recovery_key.to_public()).unwrap();

    // 1.3 Signing key: optional variable to assign to if private signing key made for DID
    let mut signing_key: Option<JWK> = None;

    // 2. Create operation
    // 2.1 Make the create patch from scratch or passed file
    let document_state = if file_path.is_none() {
        signing_key = Some(generate_key());
        let public_key_entry = PublicKeyEntry::try_from(signing_key.clone().unwrap());
        DocumentState {
            public_keys: Some(vec![public_key_entry.unwrap()]),
            services: None,
        }
    } else {
        // 2. Load document from file if passed
        let contents = std::fs::read_to_string(file_path.unwrap())
            .expect("Should have been able to read the file");
        let document: Document = serde_json::from_str(&contents).unwrap();
        document_as_document_state(&document)
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

    // 4. Writing to file
    // 4.1 Writing keys
    save_key(&did_short, KeyType::UpdateKey, &update_key);
    save_key(&did_short, KeyType::RecoveryKey, &recovery_key);
    if signing_key.is_some() {
        save_key(&did_short, KeyType::SigningKey, &signing_key.unwrap());
    }

    // 4.2 Write create operation to push to ION server
    // TODO: use publisher to push JSON directly to ION server
    std::fs::write(
        format!("create_operation_{}.json", did_short),
        to_json(&operation).unwrap(),
    )
    .unwrap();
}
