use clap::{arg, command, Arg, ArgAction};
use did_ion::sidetree::DIDStatePatch;
use did_ion::sidetree::{
    DIDSuffix, Operation, ServiceEndpointEntry, Sidetree, SidetreeDID, SidetreeOperation,
};
use did_ion::sidetree::{DocumentState, PublicKeyEntry, PublicKeyJwk};
use did_ion::ION;
use serde_json::{to_string_pretty as to_json, Map, Value};
use ssi::did::ServiceEndpoint;
use ssi::jwk::{Base64urlUInt, ECParams, Params, JWK};
use std::convert::TryFrom;
use std::fmt::format;
use std::fs::{read, write};

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
    // ---------------------------------------
    // Deactivate operation
    // ---------------------------------------

    // Take short-form DID as command line argument
    let matches = command!()
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .action(ArgAction::SetTrue),
        )
        .arg(
            arg!(-d --did <DID>)
                .required(true)
                .help("Input the short-form DID suffix to deactivate"),
        )
        .get_matches();

    let did_short = matches.get_one::<String>("did").unwrap();

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
