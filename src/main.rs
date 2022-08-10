use did_ion::sidetree::DIDStatePatch;
use did_ion::sidetree::{
    DIDSuffix, Operation, ServiceEndpointEntry, Sidetree, SidetreeDID, SidetreeOperation,
};
use did_ion::sidetree::{DocumentState, PublicKeyEntry, PublicKeyJwk};
use did_ion::ION;
use ssi::did::ServiceEndpoint;
use ssi::jwk::{Base64urlUInt, ECParams, Params, JWK};
use std::convert::TryFrom;
use std::fs::{read, write};
// use anyhow::{anyhow, bail, ensure, Context, Error as AError, Result as AResult};
// use failure::Fail;
use serde_json::{to_string_pretty as to_json, Map, Value};
// use failure::result_ext::ResultExt;

fn make_did_ion(suffix: &String) -> String {
    "did:ion:test:".to_string() + suffix
}

fn load_key(file_name: &str) -> JWK {
    // Load previous data
    let ec_read = std::fs::read(file_name).unwrap();
    let ec_read = std::str::from_utf8(&ec_read).unwrap();
    let ec_json: Map<String, Value> = serde_json::from_str(ec_read).unwrap();
    let ec_params = ECParams {
        curve: Some(ec_json["crv"].to_string().replace("\"", "")),
        // kty: Some(ec_json["kty"].to_string()),
        x_coordinate: Some(Base64urlUInt(ec_json["x"].to_string().as_bytes().to_vec())),
        y_coordinate: Some(Base64urlUInt(ec_json["y"].to_string().as_bytes().to_vec())),
        ecc_private_key: Some(Base64urlUInt(ec_json["d"].to_string().as_bytes().to_vec())),
    };

    // };
    let ec_params = Params::EC(ec_params);

    // println!("{:?}", ec_params);
    let update_key = JWK::from(ec_params);
    ION::validate_key(&update_key);
    update_key
}

fn main() {
    // Public key entries can look like this
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
    ION::validate_key(&recovery_key);
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
    let patch = DIDStatePatch::Replace { document };
    patches.push(patch.clone());
    println!("{}", to_json(&patch.clone()).unwrap());

    // Make the create opertion
    let operation = ION::create_existing(&update_pk, &recovery_pk, patches).unwrap();
    println!("{:?}", operation.clone());

    // Verify the enum
    let partially_verified_create_operation = operation.clone().partial_verify::<ION>().unwrap();
    println!("Vefification: {:?}", partially_verified_create_operation);

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
    let proof = (make_did_ion(&did_short), patch);
    let proof_json = to_json(&proof).unwrap();
    let proof_json_bytes = ION::hash(proof_json.as_bytes());
    let signed_data =
        ssi::jwt::encode_sign(algorithm, &proof_json_bytes, &verification_key).unwrap();
    println!("Proof json (data to be signed): {}", proof_json);
    println!("Signed short DID and patch: {}", signed_data);

    // Writing to file
    std::fs::write("create_operation.json", to_json(&operation).unwrap()).unwrap();
    // std::fs::write("create_operation_2.json", to_json(&create_operation).unwrap()).unwrap();
    std::fs::write("update_key.json", to_json(&update_key).unwrap()).unwrap();
    std::fs::write("signing_key.json", to_json(&verification_key).unwrap()).unwrap();
    std::fs::write("recovery_key.json", to_json(&recovery_key).unwrap()).unwrap();
    std::fs::write("signed_data.json", to_json(&signed_data).unwrap()).unwrap();
    std::fs::write("did_short.json", to_json(&did_short).unwrap()).unwrap();

    // --------------------------
    // Update operation
    // --------------------------

    // Create an update request with the signed proof added as a service
    let new_update_key = ION::generate_key().unwrap();
    ION::validate_key(&new_update_key).unwrap();
    let new_update_pk = PublicKeyJwk::try_from(new_update_key.to_public()).unwrap();

    let mut obj: Map<String, Value> = Map::new();
    obj.insert("proof".to_string(), Value::from(signed_data.clone()));

    // Update patches
    let mut patches = vec![];
    let patch = DIDStatePatch::AddServices {
        services: vec![ServiceEndpointEntry {
            id: "controller-proof".to_string(),
            r#type: "signature".to_string(),
            service_endpoint: ServiceEndpoint::Map(serde_json::Value::Object(obj.clone())),
        }],
    };
    patches.push(patch.clone());
    println!("{}", to_json(&patch.clone()).unwrap());
    let update_operation =
        ION::update(DIDSuffix(did_short), &update_key, &new_update_pk, patches).unwrap();

    // Verify the enum
    let partially_verified_update_operation = operation.clone().partial_verify::<ION>().unwrap();
    println!("Vefification: {:?}", partially_verified_update_operation);

    // Print JSON operation
    println!("{}", to_json(&update_operation).unwrap());
    let operation = Operation::Update(update_operation.clone());
    std::fs::write("update_operation.json", to_json(&operation).unwrap()).unwrap();
    std::fs::write("new_update_key.json", to_json(&new_update_key).unwrap()).unwrap();

    // --------------------------
    // Load keys and data instead for update
    // --------------------------
    // Load update key
    let update_key = load_key("update_key.json");

    // Load previous signed data
    let signed_data = std::str::from_utf8(&std::fs::read("signed_data.json").unwrap())
        .unwrap()
        .to_string()
        .replace("\"", "");
    let did_short = std::str::from_utf8(&std::fs::read("did_short.json").unwrap())
        .unwrap()
        .to_string()
        .replace("\"", "");
    println!("{:?}", signed_data);
    println!("{:?}", did_short);

    // Make update again but only using loaded data
    let mut patches = vec![];
    let patch = DIDStatePatch::AddServices {
        services: vec![ServiceEndpointEntry {
            id: "controller-proof".to_string(),
            r#type: "signature".to_string(),
            service_endpoint: ServiceEndpoint::Map(serde_json::Value::Object(obj.clone())),
        }],
    };
    patches.push(patch.clone());
    println!("{}", to_json(&patch.clone()).unwrap());

    println!("{}", to_json(&update_key).unwrap());

    let update_operation =
        ION::update(DIDSuffix(did_short), &update_key, &new_update_pk, patches).unwrap();

    // Verify the enum
    let partially_verified_update_operation = operation.clone().partial_verify::<ION>().unwrap();
    println!("Vefification: {:?}", partially_verified_update_operation);

    // Print JSON operation
    println!("{}", to_json(&update_operation).unwrap());
    let operation = Operation::Update(update_operation.clone());
    std::fs::write("update_operation_loaded.json", to_json(&operation).unwrap()).unwrap();
    // std::fs::write("update_operation_2.json", to_json(&update_operation).unwrap()).unwrap();
    std::fs::write("new_update_key.json", to_json(&new_update_key).unwrap()).unwrap();
}
