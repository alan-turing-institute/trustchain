//! Binary to attest and verify credentials.
use clap::{arg, Arg, ArgAction, Command};
use serde_json::to_string_pretty as to_json;
use ssi::vc::{Credential, URI};
use trustchain_core::{attestor::CredentialAttestor, verifier::Verifier, ROOT_EVENT_TIME_2378493};
use trustchain_ion::{attestor::IONAttestor, test_resolver, verifier::IONVerifier};

fn cli() -> Command {
    Command::new("vc")
        .about("Verifiable credential attest and verification")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .allow_external_subcommands(true)
        .subcommand(
            Command::new("attest")
                .about("Attests to credential")
                .arg(
                    Arg::new("verbose")
                        .short('v')
                        .long("verbose")
                        .action(ArgAction::SetTrue),
                )
                .arg(arg!(-d --did <DID>).required(true))
                .arg(arg!(-f --credential_file <CREDENTIAL_FILE>).required(true))
                .arg(arg!(--key_id <KEY_ID>).required(false)),
        )
        .subcommand(
            Command::new("verify")
                .about("Verifies credential")
                .arg(
                    Arg::new("verbose")
                        .short('v')
                        .long("verbose")
                        .action(ArgAction::SetTrue),
                )
                .arg(arg!(-f --credential_file <CREDENTIAL_FILE>).required(true))
                .arg(arg!(-t --root_event_time <ROOT_EVENT_TIME>).required(false)),
        )
}

fn main() {
    let matches = cli().get_matches();

    let resolver = test_resolver("http://localhost:3000/");

    match matches.subcommand() {
        Some(("attest", sub_matches)) => {
            let did = sub_matches.get_one::<String>("did").unwrap();
            let path = sub_matches.get_one::<String>("credential_file").unwrap();
            let key_id = sub_matches
                .get_one::<String>("key_id")
                .map(|string| string.as_str());
            let mut credential: Credential =
                serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
            credential.issuer = Some(ssi::vc::Issuer::URI(URI::String(did.to_string())));
            let attestor = IONAttestor::new(did);
            resolver.runtime.block_on(async {
                let credential_with_proof = attestor
                    .attest_credential(&credential, key_id, &resolver)
                    .await
                    .unwrap();
                println!("{}", &to_json(&credential_with_proof).unwrap());
            });
        }
        Some(("verify", sub_matches)) => {
            let path = sub_matches.get_one::<String>("credential_file").unwrap();
            let verbose = sub_matches.get_one::<bool>("verbose");
            let root_event_time = match sub_matches.get_one::<u32>("root_event_time") {
                Some(time) => *time,
                None => ROOT_EVENT_TIME_2378493,
            };
            let credential: Credential =
                serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
            resolver.runtime.block_on(async {
                let verify_result = credential.verify(None, &resolver).await;
                if verify_result.errors.is_empty() {
                    println!("Proof... Ok")
                } else {
                    println!("Proof... Invalid\n{}", &to_json(&verify_result).unwrap());
                }
            });

            // Trustchain verify the issue
            let verifier = IONVerifier::new(test_resolver("http://localhost:3000/"));

            let issuer = match credential.issuer {
                Some(ssi::vc::Issuer::URI(URI::String(did))) => did,
                _ => panic!("No issuer present in credential."),
            };

            let result = verifier.verify(&issuer, root_event_time);

            match result {
                Ok(chain) => {
                    println!("Issuer: {}... Ok", issuer);
                    if let Some(true) = verbose {
                        let (_, doc, _) = resolver.resolve_as_result(&issuer).unwrap();
                        println!("---");
                        println!("Issuer DID doc:");
                        println!("{}", &to_json(&doc.unwrap()).unwrap());
                        println!("---");
                        println!("Chain:");
                        println!("{}", chain);
                        println!("---");
                    }
                }
                _ => {
                    println!("Issuer: {}... invalid", issuer);
                }
            }
        }
        _ => panic!("Unrecognised subcommand."),
    }
}
