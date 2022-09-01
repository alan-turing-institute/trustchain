use did_ion::sidetree::DIDStatePatch;
use did_ion::sidetree::{
    DIDSuffix, Operation, ServiceEndpointEntry, Sidetree, SidetreeDID, SidetreeOperation,
};
use did_ion::sidetree::{DocumentState, PublicKeyEntry, PublicKeyJwk};
use did_ion::ION;
use ssi::did::ServiceEndpoint;
use ssi::jwk::{Base64urlUInt, ECParams, Params, JWK};
use std::convert::TryFrom;
// use std::fmt::format;
// use std::fs::{read, write};
// use anyhow::{anyhow, bail, ensure, Context, Error as AError, Result as AResult};
// use failure::Fail;
use serde_json::{to_string_pretty as to_json, Map, Value};
// use failure::result_ext::ResultExt;

fn make_did_ion(suffix: &String) -> String {
    "did:ion:test:".to_string() + suffix
}

// fn generate_proof_data(did_suffix: &String, document: &String) -> String {
//     // Convert document into proof data
//     todo!()
// }

// fn get_proof_data(did_suffix: &String) -> String {
//     // Resolve DID

//     // Reconstruct into document
//     todo!()
// }

// fn verify_proof_data(key: PublicKeyJwk, data: &String) -> bool {
//     // Verify the signature data
//     todo!()
// }

fn load_key(file_name: &str, verbose: bool) -> JWK {
    // Load previous data
    let ec_read = std::fs::read(file_name).unwrap();
    let ec_read = std::str::from_utf8(&ec_read).unwrap();
    let ec_json: Map<String, Value> = serde_json::from_str(ec_read).unwrap();
    let ec_params = ECParams {
        curve: Some(ec_json["crv"].to_string().replace("\"", "")),
        x_coordinate: Some(
            Base64urlUInt::try_from(ec_json["x"].to_string().replace("\"", "")).unwrap(),
        ),
        y_coordinate: Some(
            Base64urlUInt::try_from(ec_json["y"].to_string().replace("\"", "")).unwrap(),
        ),
        ecc_private_key: Some(
            Base64urlUInt::try_from(ec_json["d"].to_string().replace("\"", "")).unwrap(),
        ),
    };

    let ec_params = Params::EC(ec_params);
    let update_key = JWK::from(ec_params);
    if verbose {
        println!("Valid key: {}", ION::validate_key(&update_key).is_ok());
    }
    update_key
}

fn main() {
    // Public key entries can look like this
    // TODO: can we add custom controller using this struct?
    // let public_key: PublicKeyEntry = PublicKeyEntry {
    //   "ID",
    //   "Type",
    //   Some("controller"),
    //   key,
    // }

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
    let document_data_to_be_signed = ION::json_canonicalization_scheme(&document).unwrap();

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

    // let did_suffix = ION::serialize_suffix_data(&operation);
    let did_short = ION::serialize_suffix_data(&create_operation.clone().unwrap().suffix_data)
        .unwrap()
        .to_string();
    let did_long = SidetreeDID::<ION>::from_create_operation(&create_operation.clone().unwrap())
        .unwrap()
        .to_string();
    println!("DID suffix: {:?}", did_short);
    println!("Long: {:?}", did_long);

    // Sign the DID + canonicalized document with the verification key
    let algorithm = ION::SIGNATURE_ALGORITHM;
    let proof = (did_short.clone(), document_data_to_be_signed);
    let proof_json = ION::json_canonicalization_scheme(&proof).unwrap();
    let proof_json_bytes = ION::hash(proof_json.as_bytes());
    let signed_data =
        ssi::jwt::encode_sign(algorithm, &proof_json_bytes, &verification_key).unwrap();
    println!("Proof json (data to be signed): {}", proof_json);
    println!("Signed hash of DID and patch: {}", signed_data);

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
    std::fs::write(
        format!("signed_data_{}.json", did_short),
        to_json(&signed_data).unwrap(),
    )
    .unwrap();
    std::fs::write(
        format!("did_short_{}.json", did_short),
        to_json(&did_short).unwrap(),
    )
    .unwrap();

    // ---------------------------------------
    // Update operation: loading keys and data
    // ---------------------------------------

    // Create an update request with the signed proof added as a service

    // Generate new update key for next update commitment
    let new_update_key = ION::generate_key().unwrap();
    ION::validate_key(&new_update_key).unwrap();
    let new_update_pk = PublicKeyJwk::try_from(new_update_key.to_public()).unwrap();

    // Load update key
    let update_key = load_key(&format!("update_key_{}.json", did_short)[..], true);

    // Load previous signed data and DID
    // TODO: fix parsing to come from single file output during create
    let signed_data =
        std::str::from_utf8(&std::fs::read(format!("signed_data_{}.json", did_short)).unwrap())
            .unwrap()
            .to_string()
            .replace("\"", "");
    let did_short =
        std::str::from_utf8(&std::fs::read(format!("did_short_{}.json", did_short)).unwrap())
            .unwrap()
            .to_string()
            .replace("\"", "");

    println!("Printing loaded data...");
    println!("{:?}", signed_data);
    println!("{:?}", did_short);

    // Make object for services endpoint
    let mut obj: Map<String, Value> = Map::new();
    obj.insert(
        "controller".to_string(),
        Value::from(make_did_ion(&did_short)),
    );
    obj.insert("proofValue".to_string(), Value::from(signed_data.clone()));

    // Make update again but only using loaded data
    let mut patches = vec![];
    let patch = DIDStatePatch::AddServices {
        services: vec![ServiceEndpointEntry {
            id: "trustchain-controller-proof".to_string(),
            r#type: "TrustchainProofService".to_string(),
            service_endpoint: ServiceEndpoint::Map(serde_json::Value::Object(obj.clone())),
        }],
    };
    patches.push(patch.clone());
    // println!("{}", to_json(&patch.clone()).unwrap());

    // Make update operation
    let update_operation = ION::update(
        DIDSuffix(did_short.clone()),
        &update_key,
        &new_update_pk,
        patches,
    )
    .unwrap();

    // Verify the operation enum
    let partially_verified_update_operation = operation.clone().partial_verify::<ION>();
    println!(
        "Partially verified update: {:?}",
        partially_verified_update_operation.is_ok()
    );

    // Print JSON operation
    println!("Update operation:");
    println!("{}", to_json(&update_operation).unwrap());

    // Convert to operation with all data needed for server
    let operation = Operation::Update(update_operation.clone());

    // Write update operation json and new update key
    std::fs::write(
        format!("update_operation_{}.json", did_short),
        to_json(&operation).unwrap(),
    )
    .unwrap();
    std::fs::write(
        format!("new_update_key_{}.json", did_short),
        to_json(&new_update_key).unwrap(),
    )
    .unwrap();

    // ---------------------------------------
    // Deactivate operation
    // ---------------------------------------

    // Create a deactivate request

    // Load recovery key
    let recovery_key = load_key(&format!("recovery_key_{}.json", did_short)[..], true);

    // Make deactivate operation
    let deactivate_operation = ION::deactivate(DIDSuffix(did_short.clone()), recovery_key).unwrap();

    // Verify the operation enum
    let partially_verified_deactivate_operation =
        deactivate_operation.clone().partial_verify::<ION>();
    println!(
        "Partially verified update: {:?}",
        partially_verified_deactivate_operation.is_ok()
    );

    // Print JSON operation
    println!("Deactivate operation:");
    println!("{}", to_json(&deactivate_operation).unwrap());

    // Convert to operation with all data needed for server
    let operation = Operation::Deactivate(deactivate_operation.clone());

    // Write deactivate operation json and new update key
    std::fs::write(
        format!("deactivate_operation_{}.json", did_short),
        to_json(&operation).unwrap(),
    )
    .unwrap();
}
