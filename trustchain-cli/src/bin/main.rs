//! Trustchain CLI binary
use clap::{arg, ArgAction, Command};
use core::panic;
use serde_json::to_string_pretty;
use ssi::{jsonld::ContextLoader, ldp::LinkedDataDocument, vc::Credential};
use std::{
    fs::File,
    io::{self, stdin, BufReader},
    path::PathBuf,
};
use trustchain_api::{
    api::{TrustchainDIDAPI, TrustchainVCAPI},
    TrustchainAPI,
};
use trustchain_cli::config::cli_config;
use trustchain_core::{
    utils::extract_keys, vc::CredentialError, verifier::Verifier, TRUSTCHAIN_DATA,
};
use trustchain_http::{
    attestation_encryption_utils::ssi_to_josekit_jwk,
    attestation_utils::{
        CRState, ElementwiseSerializeDeserialize, IdentityCRInitiation, TrustchainCRError,
    },
    attestor::present_identity_challenge,
    requester::{identity_response, initiate_content_challenge, initiate_identity_challenge},
};
use trustchain_ion::{
    attest::attest_operation,
    create::{create_operation, create_operation_mnemonic},
    trustchain_resolver,
    verifier::TrustchainVerifier,
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
                .about("DID functionality: create, attest, resolve.")
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
                        .arg(arg!(-f --credential_file <CREDENTIAL_FILE>).required(false))
                        .arg(arg!(--key_id <KEY_ID>).required(false)),
                )
                .subcommand(
                    Command::new("verify")
                        .about("Verifies a credential.")
                        .arg(arg!(-v - -verbose).action(ArgAction::Count))
                        .arg(arg!(-f --credential_file <CREDENTIAL_FILE>).required(false))
                        .arg(arg!(-t --root_event_time <ROOT_EVENT_TIME>).required(false))
                ),
        )
        .subcommand(
            Command::new("cr")
                .about("Challenge-response functionality for attestation challenge response process (identity and content challenge-response).")
                .subcommand_required(true)
                .arg_required_else_help(true)
                .allow_external_subcommands(true)
                .subcommand(
                    Command::new("identity")
                        .about("Identity challenge-response functionality: initiate, present, respond.")
                        .arg(arg!(-v - -verbose).action(ArgAction::SetTrue))
                        .arg(arg!(-f --file_path <FILE_PATH>).required(false))
                        .subcommand(
                            Command::new("initiate")
                            .about("Initiates a new identity challenge-response process.")
                            .arg(arg!(-v - -verbose).action(ArgAction::Count))
                            .arg(arg!(-d --did <ATTESTOR_DID>).required(true))
                        )
                        .subcommand(
                            Command::new("present")
                            .about("Produce challenge for identity CR to be presented to requestor.")
                            .arg(arg!(-v - -verbose).action(ArgAction::Count))
                            .arg(arg!(-p --path <TEMP_P_KEY_ID_FOR_PATH>).required(true))
                            .arg(arg!(-d --did <ATTESTOR_DID>).required(true))
                        )
                        .subcommand(
                            Command::new("respond")
                            .about("Produce response for identity challenge to be posted to attestor.")
                            .arg(arg!(-v - -verbose).action(ArgAction::Count))
                            .arg(arg!(-p --path <TEMP_P_KEY_ID_FOR_PATH>).required(true))
                            .arg(arg!(-d --did <ATTESTOR_DID>).required(true))
                        )
                )
                .subcommand(
                    Command::new("content")
                        .about("Content challenge-response functionality: initiate, respond.")
                        .arg(arg!(-v - -verbose).action(ArgAction::SetTrue))
                        .arg(arg!(-f --file_path <FILE_PATH>).required(false))
                        .subcommand(
                            Command::new("initiate")
                            .about("Initiates the content challenge-response process.")
                            .arg(arg!(-v - -verbose).action(ArgAction::Count))
                            .arg(arg!(-d --did <ATTESTOR_DID>).required(true))
                            .arg(arg!(--ddid <CANDIDATE_DOWNSTREAM_DID>).required(true))
                            .arg(arg!(-p --path <TEMP_P_KEY_ID_FOR_PATH>).required(true))
                        )
                    )
                .subcommand(
                    Command::new("complete")
                        .about("Check if challenge-response for attestation request has been completed.")
                        .arg(arg!(-v - -verbose).action(ArgAction::SetTrue))
                        .arg(arg!(-p --path <TEMP_P_KEY_ID_FOR_PATH>).required(true))
                        .arg(arg!(-e --entity <ATTESTOR_OR_REQUESTER>).required(true))
                )

            )
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = cli().get_matches();
    let endpoint = cli_config().ion_endpoint.to_address();
    let root_event_time: u32 = cli_config().root_event_time;
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
                    if !mnemonic {
                        // Read doc state from file path
                        let doc_state = if let Some(file_path) = file_path {
                            Some(serde_json::from_reader(File::open(file_path)?)?)
                        } else {
                            None
                        };
                        create_operation(doc_state, verbose)?;
                    } else {
                        let mut mnemonic = String::new();
                        println!("Enter a mnemonic:");
                        std::io::stdin().read_line(&mut mnemonic).unwrap();
                        create_operation_mnemonic(&mnemonic, None)?;
                    }
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
                        err @ Err(CredentialError::VerificationResultError(_)) => {
                            println!("Proof... Invalid");
                            err?;
                        }
                        err @ Err(CredentialError::NoProofPresent) => {
                            println!("Proof... ❌ (missing proof)");
                            err?;
                        }
                        err @ Err(CredentialError::MissingVerificationMethod) => {
                            println!("Proof... ❌ (missing verification method)");
                            err?;
                        }
                        err @ Err(CredentialError::NoIssuerPresent) => {
                            println!("Proof... ✅");
                            println!("Issuer... ❌ (missing issuer)");
                            err?;
                        }
                        err @ Err(CredentialError::VerifierError(_)) => {
                            println!("Proof... ✅");
                            println!("Issuer... ❌ (with verifier error)");
                            err?;
                        }
                        err @ Err(CredentialError::FailedToDecodeJWT) => {
                            println!("Proof... ❌");
                            println!("Issuer... ❌");
                            err?;
                        }
                        Ok(_) => {
                            println!("Proof... ✅");
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
        Some(("cr", sub_matches)) => match sub_matches.subcommand() {
            Some(("identity", sub_matches)) => match sub_matches.subcommand() {
                Some(("initiate", sub_matches)) => {
                    // verify DID before resolving and extracting endpoint
                    let did = sub_matches.get_one::<String>("did").unwrap();
                    let _result = verifier.verify(did, root_event_time.into()).await?;
                    let (_, doc, _) = TrustchainAPI::resolve(did, resolver).await?;
                    let services = doc.unwrap().service;

                    // user promt for org name and operator name
                    println!("Please enter your organisation name: ");
                    let mut org_name = String::new();
                    io::stdin()
                        .read_line(&mut org_name)
                        .expect("Failed to read line");

                    let mut op_name = String::new();
                    println!("Please enter your operator name: ");
                    io::stdin()
                        .read_line(&mut op_name)
                        .expect("Failed to read line");

                    println!("Organisation name: {}", org_name);
                    println!("Operator name: {}", op_name);
                    // initiate identity challenge
                    let (identity_cr_initiation, path) = initiate_identity_challenge(
                        org_name.trim(),
                        op_name.trim(),
                        &services.unwrap(),
                    )
                    .await?;
                    identity_cr_initiation.elementwise_serialize(&path)?;
                    println!("Successfully initiated attestation request.");
                    println!("You will receive more information on the challenge-response process via alternative communication channel.");
                }
                Some(("present", sub_matches)) => {
                    // get attestation request path from provided input
                    let trustchain_dir: String = std::env::var(TRUSTCHAIN_DATA)
                        .map_err(|_| TrustchainCRError::FailedAttestationRequest)?;
                    let path_to_check = sub_matches.get_one::<String>("path").unwrap();
                    let did = sub_matches.get_one::<String>("did").unwrap();
                    let path = PathBuf::new()
                        .join(trustchain_dir)
                        .join("attestor")
                        .join("attestation_requests")
                        .join(path_to_check);
                    if !path.exists() {
                        panic!("Provided attestation request not found. Path does not exist.");
                    }
                    let identity_initiation = IdentityCRInitiation::new()
                        .elementwise_deserialize(&path)
                        .unwrap();
                    // Show requester information to user and ask for confirmation to proceed
                    println!("---------------------------------");
                    println!("Requester information: ");
                    println!(
                        "{:?}",
                        identity_initiation
                            .as_ref()
                            .unwrap()
                            .requester_details
                            .as_ref()
                            .unwrap()
                    );
                    println!("---------------------------------");
                    println!("Recognise this attestation request and want to proceed? (y/n)");
                    let mut prompt = String::new();
                    io::stdin()
                        .read_line(&mut prompt)
                        .expect("Failed to read line");
                    let prompt = prompt.trim();
                    if prompt != "y" && prompt != "yes" {
                        println!("Aborting attestation request.");
                        return Ok(());
                    }

                    let temp_p_key = identity_initiation.unwrap().temp_p_key.unwrap();

                    // call function to present challenge
                    let identity_challenge = present_identity_challenge(did, &temp_p_key)?;

                    // print signed and encrypted payload to terminal
                    let payload = identity_challenge
                        .identity_challenge_signature
                        .as_ref()
                        .unwrap();
                    println!("---------------------------------");
                    println!("Signed and encrypted challenge:");
                    println!("{:?}", payload);
                    println!("---------------------------------");
                    println!("Please send the above challenge to the requester via alternative channels.");
                    println!("Before responding using the 'respond' subcommand, the requester has to save the challenge to a file named 'identity_challenge_signature.json' in the corresponding attestation request directory.");
                    println!("---------------------------------");

                    // serialise struct
                    identity_challenge.elementwise_serialize(&path)?;
                }
                Some(("respond", sub_matches)) => {
                    // get attestation request path from provided input
                    let trustchain_dir: String = std::env::var(TRUSTCHAIN_DATA)
                        .map_err(|_| TrustchainCRError::FailedAttestationRequest)?;
                    let path_to_check = sub_matches.get_one::<String>("path").unwrap();
                    let path = PathBuf::new()
                        .join(trustchain_dir)
                        .join("requester")
                        .join("attestation_requests")
                        .join(path_to_check);
                    if !path.exists() {
                        panic!("Provided attestation request not found. Path does not exist.");
                    }
                    let did = sub_matches.get_one::<String>("did").unwrap();
                    let (_, doc, _) = TrustchainAPI::resolve(did, resolver).await?;
                    let doc = doc.unwrap();
                    // extract attestor public key from did document
                    let public_keys = extract_keys(&doc);
                    let attestor_public_key_ssi = public_keys.first().unwrap();
                    let public_key = ssi_to_josekit_jwk(attestor_public_key_ssi).unwrap();
                    // service endpoint
                    let services = doc.service.unwrap();
                    let identity_challenge_response =
                        identity_response(&path, &services, &public_key).await?;
                    // serialise struct
                    identity_challenge_response.elementwise_serialize(&path)?;
                }
                _ => panic!("Unrecognised CR identity subcommand."),
            },
            Some(("content", sub_matches)) => match sub_matches.subcommand() {
                Some(("initiate", sub_matches)) => {
                    let did = sub_matches.get_one::<String>("did").unwrap();
                    let ddid = sub_matches.get_one::<String>("ddid").unwrap();
                    let path_to_check = sub_matches.get_one::<String>("path").unwrap();

                    // check attestation request path
                    let trustchain_dir: String = std::env::var(TRUSTCHAIN_DATA)
                        .map_err(|_| TrustchainCRError::FailedAttestationRequest)?;
                    let path = PathBuf::new()
                        .join(trustchain_dir)
                        .join("requester")
                        .join("attestation_requests")
                        .join(path_to_check);
                    if !path.exists() {
                        panic!("Provided attestation request not found. Path does not exist.");
                    }

                    // resolve DID, get services and attestor public key
                    let (_, doc, _) = TrustchainAPI::resolve(did, resolver).await?;
                    let doc = doc.unwrap();
                    let public_keys = extract_keys(&doc);
                    let attestor_public_key_ssi = public_keys.first().unwrap();
                    let attestor_public_key = ssi_to_josekit_jwk(attestor_public_key_ssi).unwrap();
                    let services = &doc.service.unwrap();

                    let (content_initiation, content_challenge) =
                        initiate_content_challenge(&path, ddid, services, &attestor_public_key)
                            .await?;
                    content_initiation.elementwise_serialize(&path)?;
                    content_challenge.elementwise_serialize(&path)?;
                }
                _ => panic!("Unrecognised CR content subcommand."),
            },
            Some(("complete", sub_matches)) => {
                let path_to_check = sub_matches.get_one::<String>("path").unwrap();
                let entity = sub_matches.get_one::<String>("entity").unwrap();
                let trustchain_dir: String = std::env::var(TRUSTCHAIN_DATA)
                    .map_err(|_| TrustchainCRError::FailedAttestationRequest)?;
                let path = PathBuf::new()
                    .join(trustchain_dir)
                    .join(entity)
                    .join("attestation_requests")
                    .join(path_to_check);
                let cr_state = CRState::new()
                    .elementwise_deserialize(&path)
                    .unwrap()
                    .unwrap();
                let current_state = cr_state.check_cr_status().unwrap();

                println!(
                    "State of attestation challenge-response process: {:?}",
                    current_state
                );
            }
            _ => panic!("Unrecognised CR subcommand."),
        },
        _ => panic!("Unrecognised subcommand."),
    }
    Ok(())
}
