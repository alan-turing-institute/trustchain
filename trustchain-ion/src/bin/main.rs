//! Trustchain CLI binary
use clap::{arg, ArgAction, Command};
use std::fs::File;
use trustchain_ion::{attest::attest_operation, create::create_operation, resolve::main_resolve};

fn cli() -> Command {
    Command::new("trustchain")
        .about("Trustchain CLI")
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
                        .arg(arg!(-v --verbose <VERBOSE>).action(ArgAction::SetTrue))
                        .arg(arg!(-f --file_path <FILE_PATH>).required(false)),
                )
                .subcommand(
                    Command::new("attest")
                        .about("Controller attests to a DID.")
                        .arg(arg!(-v --verbose <VERBOSE>).action(ArgAction::SetTrue))
                        .arg(arg!(-d --did <DID>).required(true))
                        .arg(arg!(-c --controlled_did <CONTROLLED_DID>).required(true))
                        .arg(arg!(-k --key_id <KEY_ID>).required(false)),
                )
                .subcommand(
                    Command::new("resolve")
                        .about("Resolves a DID.")
                        .arg(arg!(-v --verbose <VERBOSE>).action(ArgAction::SetTrue))
                        .arg(arg!(-d --did <DID>).required(true)),
                ),
        )
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = cli().get_matches();

    match matches.subcommand() {
        Some(("did", sub_matches)) => {
            match sub_matches.subcommand() {
                Some(("create", sub_matches)) => {
                    let file_path = sub_matches.get_one::<String>("file_path");
                    let verbose = matches!(sub_matches.get_one::<bool>("verbose"), Some(true));

                    // Read doc state from file path
                    let doc_state = if let Some(file_path) = file_path {
                        let f = File::open(file_path)?;
                        let doc_state = serde_json::from_reader(f)?;
                        Some(doc_state)
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
                    attest_operation(did, controlled_did, verbose)?;
                }
                Some(("resolve", sub_matches)) => {
                    let did = sub_matches.get_one::<String>("did").unwrap();
                    let verbose = matches!(sub_matches.get_one::<bool>("verbose"), Some(true));
                    main_resolve(did, verbose)?;
                }
                _ => panic!("Unrecognised DID subcommand."),
            }
        }
        _ => panic!("Unrecognised subcommand."),
    }
    Ok(())
}
