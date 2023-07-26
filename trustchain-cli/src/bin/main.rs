//! Trustchain CLI binary
use clap::{arg, ArgAction, Command};
use serde_json::to_string_pretty;
use ssi::vc::{Credential, URI};
use std::{
    fs::File,
    io::{stdin, BufReader},
};
use trustchain_api::{
    api::{TrustchainDIDAPI, TrustchainVCAPI},
    TrustchainAPI,
};
use trustchain_cli::config::cli_config;
use trustchain_ion::{attest::attest_operation, create::create_operation, get_ion_resolver};

fn cli() -> Command {
    Command::new("Trustchain CLI")
        .about(format!("Trustchain CLI v{}\n\nTrustchain command line interface for decentralised public key infrastructure.", env!("CARGO_PKG_VERSION")))
        .version(env!("CARGO_PKG_VERSION"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .subcommand_required(true)
        .arg_required_else_help(true)
        .allow_external_subcommands(true)
        .subcommand(
            Command::new("did")
                .about("DID functionality: create, attest, resolve.")
                .subcommand_required(true)
                .arg_required_else_help(true)
                .allow_external_subcommands(true)
                .subcommand(
                    Command::new("create")
                        .about("Creates a new controlled DID from a document state.")
                        .arg(arg!(-v - -verbose).action(ArgAction::SetTrue))
                        .arg(arg!(-f --file_path <FILE_PATH>).required(false)),
                )
                .subcommand(
                    Command::new("attest")
                        .about("Controller attests to a DID.")
                        .arg(arg!(-v - -verbose).action(ArgAction::SetTrue))
                        .arg(arg!(-d --did <DID>).required(true))
                        .arg(arg!(-c --controlled_did <CONTROLLED_DID>).required(true))
                        .arg(arg!(-k --key_id <KEY_ID>).required(false)),
                )
                .subcommand(
                    Command::new("resolve")
                        .about("Resolves a DID.")
                        .arg(arg!(-v - -verbose).action(ArgAction::SetTrue))
                        .arg(arg!(-d --did <DID>).required(true)),
                )
                .subcommand(
                    Command::new("verify")
                        .about("Verifies a DID.")
                        .arg(arg!(-v - -verbose).action(ArgAction::SetTrue))
                        .arg(arg!(-d --did <DID>).required(true)),
                ),
        )
        .subcommand(
            // TODO: refactor into library code
            Command::new("vc")
                .about("Verifiable credential functionality: sign and verify.")
                .subcommand_required(true)
                .arg_required_else_help(true)
                .allow_external_subcommands(true)
                .subcommand(
                    Command::new("sign")
                        .about("Signs a credential.")
                        .arg(arg!(-v - -verbose).action(ArgAction::SetTrue))
                        .arg(arg!(-d --did <DID>).required(true))
                        .arg(arg!(-f --credential_file <CREDENTIAL_FILE>).required(false))
                        .arg(arg!(--key_id <KEY_ID>).required(false)),
                )
                .subcommand(
                    Command::new("verify")
                        .about("Verifies a credential.")
                        .arg(arg!(-v - -verbose).action(ArgAction::Count))
                        .arg(arg!(-f --credential_file <CREDENTIAL_FILE>).required(false))
                        .arg(arg!(-s - -signature_only).action(ArgAction::SetTrue))
                        .arg(arg!(-t --root_event_time <ROOT_EVENT_TIME>).required(false)),
                ),
        )
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = cli().get_matches();
    let endpoint = "http://localhost:3000/";
    match matches.subcommand() {
        Some(("did", sub_matches)) => {
            match sub_matches.subcommand() {
                Some(("create", sub_matches)) => {
                    let file_path = sub_matches.get_one::<String>("file_path");
                    let verbose = matches!(sub_matches.get_one::<bool>("verbose"), Some(true));

                    // Read doc state from file path
                    let doc_state = if let Some(file_path) = file_path {
                        Some(serde_json::from_reader(File::open(file_path)?)?)
                    } else {
                        None
                    };

                    // Read from the file path to a "Reader"
                    create_operation(doc_state, verbose)?;
                }
                Some(("attest", sub_matches)) => {
                    let did = sub_matches.get_one::<String>("did").unwrap();
                    let controlled_did = sub_matches.get_one::<String>("controlled_did").unwrap();
                    let verbose = matches!(sub_matches.get_one::<bool>("verbose"), Some(true));
                    let _key_id = sub_matches
                        .get_one::<String>("key_id")
                        .map(|string| string.as_str());
                    // TODO: pass optional key_id
                    attest_operation(did, controlled_did, verbose).await?;
                }
                Some(("resolve", sub_matches)) => {
                    let did = sub_matches.get_one::<String>("did").unwrap();
                    let _verbose = matches!(sub_matches.get_one::<bool>("verbose"), Some(true));
                    let (res_meta, doc, doc_meta) =
                        TrustchainAPI::resolve(did, "http://localhost:3000/".into()).await?;
                    // Print results
                    println!("---");
                    println!("Document:");
                    if let Some(doc) = doc {
                        println!(
                            "{}",
                            to_string_pretty(&doc).expect("Cannot convert to JSON.")
                        );
                    }
                    println!("---");
                    println!("Document metadata:");
                    if let Some(doc_meta) = doc_meta {
                        println!(
                            "{}",
                            to_string_pretty(&doc_meta).expect("Cannot convert to JSON.")
                        );
                    }
                    println!("Result metadata:");
                    println!(
                        "{}",
                        to_string_pretty(&res_meta).expect("Cannot convert to JSON.")
                    );
                }
                _ => panic!("Unrecognised DID subcommand."),
            }
        }
        Some(("vc", sub_matches)) => {
            let resolver = get_ion_resolver("http://localhost:3000/");
            match sub_matches.subcommand() {
                Some(("sign", sub_matches)) => {
                    let did = sub_matches.get_one::<String>("did").unwrap();
                    let key_id = sub_matches
                        .get_one::<String>("key_id")
                        .map(|string| string.as_str());
                    let credential: Credential =
                        if let Some(path) = sub_matches.get_one::<String>("credential_file") {
                            serde_json::from_reader(&*std::fs::read(path).unwrap()).unwrap()
                        } else {
                            let buffer = BufReader::new(stdin());
                            serde_json::from_reader(buffer).unwrap()
                        };

                    let credential_with_proof =
                        TrustchainAPI::sign(credential, did, key_id, endpoint).await;
                    println!("{}", &to_string_pretty(&credential_with_proof).unwrap());
                }
                Some(("verify", sub_matches)) => {
                    let verbose = sub_matches.get_one::<u8>("verbose");
                    let signature_only = sub_matches.get_one::<bool>("signature_only");
                    let root_event_time = match sub_matches.get_one::<String>("root_event_time") {
                        Some(time) => time.parse::<u32>().unwrap(),
                        None => cli_config().root_event_time,
                    };
                    let credential: Credential =
                        if let Some(path) = sub_matches.get_one::<String>("credential_file") {
                            serde_json::from_reader(&*std::fs::read(path).unwrap()).unwrap()
                        } else {
                            let buffer = BufReader::new(stdin());
                            serde_json::from_reader(buffer).unwrap()
                        };

                    let (verify_result, result) = TrustchainAPI::verify_credential(
                        &credential,
                        *signature_only.unwrap(),
                        root_event_time,
                        endpoint,
                    )
                    .await;
                    if verify_result.errors.is_empty() {
                        println!("Proof... ✅")
                    } else {
                        println!(
                            "Proof... Invalid\n{}",
                            &to_string_pretty(&verify_result).unwrap()
                        );
                    }

                    // Return if only checking signature
                    if let Some(true) = signature_only {
                        return Ok(());
                    }

                    // // Trustchain verify the issued credential
                    // let verifier = IONVerifier::new(get_ion_resolver("http://localhost:3000/"));

                    let issuer = match credential.issuer {
                        Some(ssi::vc::Issuer::URI(URI::String(did))) => did,
                        _ => panic!("No issuer present in credential."),
                    };

                    // let result = verifier.verify(&issuer, root_event_time);

                    match result.unwrap() {
                        Ok(chain) => {
                            println!("Issuer: {}... ✅", issuer);
                            if let Some(&verbose_count) = verbose {
                                if verbose_count > 1 {
                                    let (_, doc, doc_meta) =
                                        resolver.resolve_as_result(&issuer).await.unwrap();
                                    println!("---");
                                    println!("Issuer DID doc:");
                                    println!(
                                        "{}",
                                        &to_string_pretty(&doc.as_ref().unwrap()).unwrap()
                                    );
                                    println!("---");
                                    println!("Issuer DID doc metadata:");
                                    println!(
                                        "{}",
                                        &to_string_pretty(&doc_meta.as_ref().unwrap()).unwrap()
                                    );
                                }
                                if verbose_count > 0 {
                                    println!("---");
                                    println!("Chain:");
                                    println!("{}", chain);
                                    println!("---");
                                }
                            }
                        }
                        _ => {
                            println!("Issuer: {}... ❌", issuer);
                        }
                    }
                }
                _ => panic!("Unrecognised VC subcommand."),
            }
        }
        _ => panic!("Unrecognised subcommand."),
    }
    Ok(())
}
