// use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};
use actix_web::web;
use image::EncodableLayout;
// use serde::{Deserialize, Serialize};
use serde_json::{to_string_pretty, Map, Value};
use ssi::one_or_many::OneOrMany;
use ssi::vc::Credential;
use std::io::Write;
use std::process::{Command, Stdio};

/// Converts a credential into an offer
pub fn credential_to_offer(_credential: &str) -> String {
    todo!()
}

/// Verifies a received credential
pub fn verify_vc(_credential: &web::Json<Credential>) -> String {
    todo!()
}

/// Generates a VC (prototype uses const DID and const credential file)
pub fn generate_vc(is_offer: bool, subject_id: Option<&str>, credential_id: &str) -> String {
    let command_str = format!("trustchain-cli vc attest --did did:ion:test:EiBYdto2LQd_uAj_EXEoxP_KbLmZzwe1E-vXp8ZsMv1Gpg");
    let mut command = command_str.split(" ").skip(1).fold(
        Command::new(command_str.split_once(' ').unwrap().0),
        |mut cmd, s| {
            cmd.arg(s);
            cmd
        },
    );
    println!("{:?}", command);
    command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::piped());

    // Read credential as string
    let home = std::env::var("HOME").unwrap();
    let file_str = format!("{home}/.trustchain/credentials/credential_template.jsonld");
    let mut credential: Credential =
        serde_json::from_reader(std::fs::read(file_str).unwrap().as_bytes()).unwrap();

    // Add passed credential_id
    credential.id = Some(ssi::vc::URI::String(format!(
        "urn:uuid:{}",
        credential_id.to_string()
    )));

    // Add subject_id if not none
    if let Some(subject_id_str) = subject_id {
        if let OneOrMany::One(ref mut subject) = credential.credential_subject {
            subject.id = Some(ssi::vc::URI::String(subject_id_str.to_string()));
        }
    }
    // Use stdin to pass credential string
    let mut child = command.spawn().expect("Failed to spawn child process");
    let mut stdin = child.stdin.take().expect("Failed to open stdin");
    std::thread::spawn(move || {
        stdin
            .write_all(serde_json::to_string(&credential).unwrap().as_bytes())
            .expect("Failed to write to stdin");
    });
    // Execute
    let output = child.wait_with_output().expect("Failed to read stdout");

    println!("{}", String::from_utf8(output.clone().stdout).unwrap());
    println!("{}", String::from_utf8(output.clone().stderr).unwrap());

    let vc_string = String::from_utf8(output.clone().stdout).unwrap();

    // Credential offer structure
    // {
    //   "type":"CredentialOffer",
    //   "credentialPreview":{<CREDENTIAL_PREVIEW>},
    //   "expires":"2022-12-20T14:19:49Z"
    // }

    if !is_offer {
        // let vc_string = serde_json::to_string_pretty(&vc).unwrap();
        println!("CREDENTIAL:\n{}", vc_string);
        vc_string
    } else {
        // If offer on
        let mut vc: Map<String, Value> = serde_json::from_str(vc_string.as_str()).unwrap();

        // Remove proof
        vc.remove("proof");

        // Make our credential offer
        let mut offer: Map<String, Value> = Map::new();

        // Type: credential offer
        offer.insert(
            "type".to_string(),
            Value::String("CredentialOffer".to_string()),
        );

        // Preview with the VC excluding proof
        offer.insert("credentialPreview".to_string(), Value::Object(vc));

        // Insert expiry time for using offer within next hour
        let expiry_time = chrono::offset::Utc::now() + chrono::Duration::minutes(60);
        offer.insert(
            "expires".to_string(),
            Value::String(expiry_time.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()),
        );
        println!("OFFER:");
        println!("{}", to_string_pretty(&offer).unwrap());
        String::from_utf8(serde_json::to_string(&offer).unwrap().into_bytes()).unwrap()
    }
}
