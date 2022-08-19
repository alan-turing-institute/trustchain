use did_ion::sidetree::DIDStatePatch;
use did_ion::sidetree::{DocumentState, PublicKeyEntry, PublicKeyJwk};
use did_ion::sidetree::{Operation, Sidetree, SidetreeDID, SidetreeOperation};
use did_ion::ION;

use serde_json::to_string_pretty as to_json;
use std::convert::TryFrom;

// fn make_did_ion(suffix: &String) -> String {
//     "did:ion:test:".to_string() + suffix
// }

// fn load_key(file_name: &str, verbose: bool) -> JWK {
//     // Load previous data
//     let ec_read = std::fs::read(file_name).unwrap();
//     let ec_read = std::str::from_utf8(&ec_read).unwrap();
//     let ec_json: Map<String, Value> = serde_json::from_str(ec_read).unwrap();
//     let ec_params = ECParams {
//         curve: Some(ec_json["crv"].to_string().replace("\"", "")),
//         x_coordinate: Some(
//             Base64urlUInt::try_from(ec_json["x"].to_string().replace("\"", "")).unwrap(),
//         ),
//         y_coordinate: Some(
//             Base64urlUInt::try_from(ec_json["y"].to_string().replace("\"", "")).unwrap(),
//         ),
//         ecc_private_key: Some(
//             Base64urlUInt::try_from(ec_json["d"].to_string().replace("\"", "")).unwrap(),
//         ),
//     };

//     let ec_params = Params::EC(ec_params);
//     let update_key = JWK::from(ec_params);
//     if verbose {
//         println!("Valid key: {}", ION::validate_key(&update_key).is_ok());
//     }
//     update_key
// }

fn main() {
    // --------------------------
    // Make some keys
    // --------------------------
    let update_key = ION::generate_key();
    let recovery_key = ION::generate_key();
    let verification_key = ION::generate_key().unwrap();

    // Get keys in form for DID
    let update_key = update_key.unwrap();
    ION::validate_key(&update_key).unwrap();
    let update_pk = PublicKeyJwk::try_from(update_key.to_public()).unwrap();

    let recovery_key = recovery_key.unwrap();
    ION::validate_key(&recovery_key).unwrap();
    let recovery_pk = PublicKeyJwk::try_from(recovery_key.to_public()).unwrap();

    // --------------------------
    // Create operation
    // --------------------------
    // Make the create patch
    let mut patches = vec![];
    let public_key_entry = PublicKeyEntry::try_from(verification_key.clone());
    let document = DocumentState {
        public_keys: Some(vec![public_key_entry.unwrap()]),
        services: None,
    };

    // Make patch from document
    let patch = DIDStatePatch::Replace { document };
    patches.push(patch.clone());

    // Make the create operation from pathces
    let operation = ION::create_existing(&update_pk, &recovery_pk, patches).unwrap();
    // println!("Create operation:");

    // Verify the enum
    let partially_verified_create_operation = operation.clone().partial_verify::<ION>();
    println!(
        "Partially verified create: {}",
        partially_verified_create_operation.is_ok()
    );

    // Get the data of the operation enum
    let create_operation = match operation.clone() {
        Operation::Create(x) => Some(x),
        _ => None,
    };

    // Print JSON operation
    println!("Create operation:");
    println!("{}", to_json(&create_operation).unwrap());

    let did_short = ION::serialize_suffix_data(&create_operation.clone().unwrap().suffix_data)
        .unwrap()
        .to_string();
    let did_long = SidetreeDID::<ION>::from_create_operation(&create_operation.clone().unwrap())
        .unwrap()
        .to_string();
    println!("DID suffix: {:?}", did_short);
    println!("Long: {:?}", did_long);

    // Writing to file
    std::fs::write(
        format!("create_operation_{}.json", did_short),
        to_json(&operation).unwrap(),
    )
    .unwrap();
    std::fs::write(
        format!("update_key_{}.json", did_short),
        to_json(&update_key).unwrap(),
    )
    .unwrap();
    std::fs::write(
        format!("signing_key_{}.json", did_short),
        to_json(&verification_key).unwrap(),
    )
    .unwrap();
    std::fs::write(
        format!("recovery_key_{}.json", did_short),
        to_json(&recovery_key).unwrap(),
    )
    .unwrap();
}
