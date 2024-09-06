//! Trustchain CLI binary
use clap::{arg, ArgAction, Command};
use serde_json::to_string_pretty;
use ssi::{jsonld::ContextLoader, ldp::LinkedDataDocument, vc::Credential};
use std::{
    fs::File,
    io::{stdin, BufReader},
    path::Path,
};
use trustchain_api::{
    api::{TrustchainDIDAPI, TrustchainDataAPI, TrustchainVCAPI},
    TrustchainAPI,
};
use trustchain_cli::config::cli_config;
use trustchain_core::{
    vc::{CredentialError, DataCredentialError},
    verifier::Verifier,
    JSON_FILE_EXTENSION,
};
use trustchain_ion::{
    attest::attest_operation,
    create::{create_operation, create_operation_mnemonic},
    trustchain_resolver,
    verifier::TrustchainVerifier,
    CREATE_OPERATION_FILENAME_PREFIX,
};

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
                .about("DID functionality: create, attest, resolve, verify.")
                .subcommand_required(true)
                .arg_required_else_help(true)
                .allow_external_subcommands(true)
                .subcommand(
                    Command::new("create")
                        .about("Creates a new controlled DID from a document state.")
                        .arg(arg!(-v - -verbose).action(ArgAction::SetTrue))
                        .arg(arg!(-m - -mnemonic).action(ArgAction::SetTrue))
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
                        .arg(arg!(-d --did <DID>).required(true))
                        .arg(arg!(-t --root_event_time <ROOT_EVENT_TIME>).required(false))
                ),
        )
        .subcommand(
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
                        // TODO: credential file Should be required?
                        .arg(arg!(-f --credential_file <CREDENTIAL_FILE>).required(false))
                        .arg(arg!(--key_id <KEY_ID>).required(false)),
                )
                .subcommand(
                    Command::new("verify")
                        .about("Verifies a credential.")
                        .arg(arg!(-v - -verbose).action(ArgAction::Count))
                        // TODO: credential file Should be required?
                        .arg(arg!(-f --credential_file <CREDENTIAL_FILE>).required(false))
                        .arg(arg!(-t --root_event_time <ROOT_EVENT_TIME>).required(false)),
                ),
        )
        .subcommand(
            Command::new("data")
                .about("Data provenance functionality: sign and verify.")
                .subcommand_required(true)
                .arg_required_else_help(true)
                .allow_external_subcommands(true)
                .subcommand(
                    Command::new("sign")
                        .about("Signs the data in the given file.")
                        .arg(arg!(-v - -verbose).action(ArgAction::SetTrue))
                        .arg(arg!(-d --did <DID>).required(true))
                        .arg(arg!(-f --data_file <DATA_FILE>).required(true))
                        .arg(arg!(--key_id <KEY_ID>).required(false)),
                )
                .subcommand(
                    Command::new("verify")
                        .about("Verifies a data credential.")
                        .arg(arg!(-v - -verbose).action(ArgAction::Count))
                        .arg(arg!(-f --data_file <DATA_FILE>).required(true))
                        .arg(arg!(-c --credential_file <CREDENTIAL_FILE>).required(true))
                        .arg(arg!(-t --root_event_time <ROOT_EVENT_TIME>).required(false)),
                ),
        )
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = cli().get_matches();
    let endpoint = cli_config().ion_endpoint.to_address();
    let verifier = TrustchainVerifier::new(trustchain_resolver(&endpoint));
    let resolver = verifier.resolver();
    let mut context_loader = ContextLoader::default();
    match matches.subcommand() {
        Some(("did", sub_matches)) => {
            match sub_matches.subcommand() {
                Some(("create", sub_matches)) => {
                    let file_path = sub_matches.get_one::<String>("file_path");
                    let verbose = matches!(sub_matches.get_one::<bool>("verbose"), Some(true));
                    let mnemonic = matches!(sub_matches.get_one::<bool>("mnemonic"), Some(true));
                    if mnemonic && file_path.is_some() {
                        panic!("Please use only one of '--file_path' and '--mnemonic'.")
                    }
                    let filename = if !mnemonic {
                        // Read doc state from file path
                        let doc_state = if let Some(file_path) = file_path {
                            Some(serde_json::from_reader(File::open(file_path)?)?)
                        } else {
                            None
                        };
                        create_operation(doc_state, verbose)?
                    } else {
                        let mut mnemonic = String::new();
                        println!("Enter a mnemonic:");
                        std::io::stdin().read_line(&mut mnemonic).unwrap();
                        create_operation_mnemonic(&mnemonic, None)?
                    };
                    println!(
                        "Created new DID: {}",
                        filename
                            .strip_prefix(CREATE_OPERATION_FILENAME_PREFIX)
                            .unwrap_or_else(|| &filename)
                            .strip_suffix(JSON_FILE_EXTENSION)
                            .unwrap_or_else(|| &filename)
                    );
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
                // TODO: add a flag for update operation with a mnemonic to add a
                // key generated on mobile to the DID.
                Some(("resolve", sub_matches)) => {
                    let did = sub_matches.get_one::<String>("did").unwrap();
                    let _verbose = matches!(sub_matches.get_one::<bool>("verbose"), Some(true));
                    let (res_meta, doc, doc_meta) = TrustchainAPI::resolve(did, resolver).await?;
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
                Some(("verify", sub_matches)) => {
                    let did = sub_matches.get_one::<String>("did").unwrap();
                    let root_event_time = match sub_matches.get_one::<String>("root_event_time") {
                        Some(time) => time.parse::<u32>().unwrap(),
                        None => cli_config().root_event_time,
                    };
                    let did_chain =
                        TrustchainAPI::verify(did, root_event_time.into(), &verifier).await?;
                    println!("{did_chain}");
                }
                _ => panic!("Unrecognised DID subcommand."),
            }
        }
        Some(("vc", sub_matches)) => {
            let verifier = TrustchainVerifier::new(trustchain_resolver(&endpoint));
            let resolver = verifier.resolver();
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

                    let credential_with_proof = TrustchainAPI::sign(
                        credential,
                        did,
                        None,
                        key_id,
                        resolver,
                        &mut context_loader,
                    )
                    .await
                    .expect("Failed to issue credential.");
                    println!("{}", &to_string_pretty(&credential_with_proof).unwrap());
                }
                Some(("verify", sub_matches)) => {
                    let verbose = sub_matches.get_one::<u8>("verbose");
                    let root_event_time = match sub_matches.get_one::<String>("root_event_time") {
                        Some(time) => time.parse::<u64>().unwrap(),
                        None => cli_config().root_event_time.into(),
                    };
                    // Deserialize
                    let credential: Credential =
                        if let Some(path) = sub_matches.get_one::<String>("credential_file") {
                            serde_json::from_reader(&*std::fs::read(path).unwrap()).unwrap()
                        } else {
                            let buffer = BufReader::new(stdin());
                            serde_json::from_reader(buffer).unwrap()
                        };
                    // Verify credential
                    let verify_result = TrustchainAPI::verify_credential(
                        &credential,
                        None,
                        root_event_time,
                        &verifier,
                        &mut context_loader,
                    )
                    .await;
                    // Handle result
                    match verify_result {
                        Err(cred_err) => {
                            handle_credential_error(cred_err)?;
                        }
                        Ok(_) => {
                            println!("Proof.... ✅");
                            println!("Issuer... ✅");
                        }
                    }

                    // Show chain
                    if let Some(&verbose_count) = verbose {
                        let issuer = credential
                            .get_issuer()
                            .expect("No issuer present in credential.");
                        let chain = TrustchainAPI::verify(issuer, root_event_time, &verifier)
                            .await
                            // Can unwrap as already verified above.
                            .unwrap();
                        if verbose_count > 1 {
                            let (_, doc, doc_meta) =
                                resolver.resolve_as_result(issuer).await.unwrap();
                            println!("---");
                            println!("Issuer DID doc:");
                            println!("{}", &to_string_pretty(&doc.as_ref().unwrap()).unwrap());
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
                _ => panic!("Unrecognised VC subcommand."),
            }
        }
        Some(("data", sub_matches)) => {
            let verifier = TrustchainVerifier::new(trustchain_resolver(&endpoint));
            let resolver = verifier.resolver();
            match sub_matches.subcommand() {
                Some(("sign", sub_matches)) => {
                    let did = sub_matches.get_one::<String>("did").unwrap();
                    let key_id = sub_matches
                        .get_one::<String>("key_id")
                        .map(|string| string.as_str());
                    let data = Path::new(sub_matches.get_one::<String>("data_file").unwrap());
                    let bytes = std::fs::read(data).unwrap(); // TODO: handle with ? or expect.

                    let data_with_proof = TrustchainAPI::sign_data(
                        &bytes,
                        did,
                        None,
                        key_id,
                        resolver,
                        &mut context_loader,
                    )
                    .await
                    .expect("Failed to sign data.");
                    println!("{}", &to_string_pretty(&data_with_proof).unwrap());
                }
                Some(("verify", sub_matches)) => {
                    let verbose = sub_matches.get_one::<u8>("verbose");
                    let root_event_time = match sub_matches.get_one::<String>("root_event_time") {
                        Some(time) => time.parse::<u64>().unwrap(),
                        None => cli_config().root_event_time.into(),
                    };
                    let data = Path::new(sub_matches.get_one::<String>("data_file").unwrap());
                    // Deserialize
                    let credential: Credential =
                        if let Some(path) = sub_matches.get_one::<String>("credential_file") {
                            serde_json::from_reader(&*std::fs::read(path).unwrap()).unwrap()
                        } else {
                            let buffer = BufReader::new(stdin());
                            serde_json::from_reader(buffer).unwrap()
                        };
                    let bytes = std::fs::read(data).unwrap(); // TODO: handle with ? or expect.

                    let verify_result = TrustchainAPI::verify_data(
                        &bytes,
                        &credential,
                        None,
                        root_event_time,
                        &verifier,
                        &mut context_loader,
                    )
                    .await;
                    // Handle result
                    match verify_result {
                        Err(DataCredentialError::CredentialError(cred_err)) => {
                            handle_credential_error(cred_err)?;
                        }
                        Err(DataCredentialError::MismatchedHashDigests(_, _)) => {
                            println!("Digest... ❌ (mismatched data hash digests)");
                        }
                        Err(DataCredentialError::MissingAttribute(att)) => {
                            println!("Invalid credential... ❌ (missing attribute: \"{att}\")");
                        }
                        Err(DataCredentialError::ManyCredentialSubject(subjects)) => {
                            println!("Invalid credential... ❌ (only one subject permitted, multiple subjects found: {subjects:?})");
                        }
                        Ok(_) => {
                            println!("Proof.... ✅");
                            println!("Issuer... ✅");
                            println!("Digest... ✅");
                        }
                    };
                    // Show chain
                    if let Some(&verbose_count) = verbose {
                        let issuer = credential
                            .get_issuer()
                            .expect("No issuer present in credential.");
                        let chain = TrustchainAPI::verify(issuer, root_event_time, &verifier)
                            .await
                            // Can unwrap as already verified above.
                            .unwrap();
                        // TODO: avoid repetition (see vc subcommand above):
                        if verbose_count > 1 {
                            let (_, doc, doc_meta) =
                                resolver.resolve_as_result(issuer).await.unwrap();
                            println!("---");
                            println!("Issuer DID doc:");
                            println!("{}", &to_string_pretty(&doc.as_ref().unwrap()).unwrap());
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
                _ => panic!("Unrecognised DATA subcommand."),
            }
        }
        _ => panic!("Unrecognised subcommand."),
    }
    Ok(())
}

fn handle_credential_error(err: CredentialError) -> Result<(), CredentialError> {
    match err {
        CredentialError::VerificationResultError(_) => {
            println!("Proof... ❌ Invalid");
        }
        CredentialError::NoProofPresent => {
            println!("Proof... ❌ (missing proof)");
        }
        CredentialError::MissingVerificationMethod => {
            println!("Proof... ❌ (missing verification method)");
        }
        CredentialError::NoIssuerPresent => {
            println!("Proof.... ✅");
            println!("Issuer... ❌ (missing issuer)");
        }
        CredentialError::VerifierError(_) => {
            println!("Proof.... ✅");
            println!("Issuer... ❌ (with verifier error)");
        }
        CredentialError::FailedToDecodeJWT => {
            println!("Proof.... ❌");
            println!("Issuer... ❌");
        }
    }
    Err(err)
}
