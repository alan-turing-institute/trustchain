use did_ion::sidetree::DIDStatePatch;
use did_ion::sidetree::{CreateOperation, Operation, Sidetree, SidetreeDID, SidetreeOperation};
use did_ion::sidetree::{DocumentState, PublicKeyEntry, PublicKeyJwk};
use did_ion::{DIDION, ION};
use std::convert::TryFrom;
// use anyhow::{anyhow, bail, ensure, Context, Error as AError, Result as AResult};
// use failure::Fail;
use serde_json::to_string_pretty as to_json;
// use failure::result_ext::ResultExt;

fn main() {
    // Public key entries can look like this
    // let public_key: PublicKeyEntry = PublicKeyEntry {
    //   "ID",
    //   "Type",
    //   Some("controller"),
    //   key,
    // }

    // Make some keys
    let update_key = ION::generate_key();
    let recovery_key = ION::generate_key();
    let verification_key = ION::generate_key().unwrap();

    // Get keys in form for DID
    let update_key = update_key.unwrap();
    ION::validate_key(&update_key).unwrap();
    let update_pk = PublicKeyJwk::try_from(update_key.to_public()).unwrap();

    let recovery_key = recovery_key.unwrap();
    ION::validate_key(&recovery_key);
    let recovery_pk = PublicKeyJwk::try_from(recovery_key.to_public()).unwrap();

    // Make the create patch
    let mut patches = vec![];
    let public_key_entry = PublicKeyEntry::try_from(verification_key.clone());
    let document = DocumentState {
        public_keys: Some(vec![public_key_entry.unwrap()]),
        services: None,
    };
    let patch = DIDStatePatch::Replace { document };
    patches.push(patch.clone());
    println!("{}", to_json(&patch.clone()).unwrap());

    // Make the create opertion
    let operation = ION::create_existing(&update_pk, &recovery_pk, patches).unwrap();
    println!("{:?}", operation.clone());

    // Verify the enum
    let pcop = operation.clone().partial_verify::<ION>().unwrap();
    println!("Vefification: {:?}", pcop);

    // Get the data of the operation enum
    let create_operation = match operation.clone() {
        Operation::Create(x) => Some(x),
        _ => None,
    };

    // Print JSON operation
    println!("{}", to_json(&create_operation).unwrap());

    // let did_suffix = ION::serialize_suffix_data(&operation);
    let did_short = ION::serialize_suffix_data(&create_operation.clone().unwrap().suffix_data)
        .unwrap()
        .to_string();
    let did_long = SidetreeDID::<ION>::from_create_operation(&create_operation.clone().unwrap())
        .unwrap()
        .to_string();
    println!("Short: {:?}", did_short);
    println!("Long: {:?}", did_long);

    // Sign the DID + JSON patch with the verification key
    let algorithm = ION::SIGNATURE_ALGORITHM;
    let proof = (did_short, patch);
    let proof_json = to_json(&proof).unwrap();
    let proof_json_bytes = ION::hash(proof_json.as_bytes());
    let signed_data =
        ssi::jwt::encode_sign(algorithm, &proof_json_bytes, &verification_key).unwrap();
    println!("Proof json (data to be signed): {}", proof_json);
    println!("Signed short DID and patch: {}", signed_data);

    // Writing to file
    std::fs::write("create_operation.json", to_json(&create_operation).unwrap());
    std::fs::write("update_key.json", to_json(&update_key).unwrap());
    std::fs::write("signing_key.json", to_json(&verification_key).unwrap());
    std::fs::write("recovery_key.json", to_json(&recovery_key).unwrap());

    // Create an update request with the signed proof added as a service
    // TODO
}
