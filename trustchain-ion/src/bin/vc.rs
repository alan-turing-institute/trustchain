//! Binary to attest and verify credentials.
use clap::{arg, Arg, ArgAction, Command};
use serde_json::to_string_pretty as to_json;
use ssi::vc::{Credential, URI};
use trustchain_core::attestor::CredentialAttestor;
use trustchain_ion::{attestor::IONAttestor, test_resolver};

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
                .arg(arg!(-f --credential_file <CREDENTIAL_FILE>).required(true)),
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
            let credential: Credential =
                serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
            resolver.runtime.block_on(async {
                let verify_result = credential.verify(None, &resolver).await;
                if verify_result.errors.is_empty() {
                    println!("Ok.")
                } else {
                    println!("Invalid:\n{}", &to_json(&verify_result).unwrap());
                }
            });
        }
        _ => panic!("Unrecognised subcommand."),
    }
}
