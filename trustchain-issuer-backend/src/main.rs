use actix_web::{
    get, http::header::ContentType, post, web, App, FromRequest, HttpResponse, HttpServer,
    Responder,
};
use execute::Execute;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{Map, Value};
use std::{
    env,
    process::{Command, Stdio},
    str::from_boxed_utf8_unchecked,
};
// use serde_json::{Deserialize, Serialize};

// Process sketch:
// 1. Receive POST request from frontend
// 2. Process request, calling generate VC (as offer)
// 3. Handle outputted VC (cache?)
// 4. Create service for frontend that provides a URI (vc/{uuid})
// 5. Create service for holder that provides JSON VC offer upon
//    GET request to URI
// 6. Credible responds with a POST request

#[get("/hello/{name}")]
async fn greet(name: web::Path<String>) -> impl Responder {
    format!("Hello {name}!")
}

fn get_vc_by_uuid(uuid: web::Path<String>) -> String {
    // "A".to_string()
    generate_vc(true, None)
}

/// API endpoint taking the UUID of a VC. Response is the VC JSON.
// #[get("/vc/{uuid}")]
#[get("/vc/abc")]
// async fn get_vc_offer(uuid: web::Path<String>) -> impl Responder {
async fn get_vc_offer() -> impl Responder {
    // cli_echo();
    get_vc_by_uuid(web::Path::<String>::from("abc".to_string()))
}

#[derive(Deserialize, Serialize, Clone, Debug)]
struct VcInfo {
    subject_id: String,
}

// impl FromRequest for VcInfo {
//     fn from_request(req: &actix_web::HttpRequest, payload: &mut actix_web::dev::Payload) -> Self::Future {

//     }
// }

// #[post("/vc/{uuid}")]
#[post("/vc/abc")]
// async fn post_request(info: web::Json<VcInfo>) -> impl Responder {
// async fn post_request(info: web::Form<VcInfo>) -> impl Responder {
async fn post_request(info: web::Json<VcInfo>) -> impl Responder {
    // async fn post_request(uuid: web::Path<String>, info: web::Json<VcInfo>) -> impl Responder {
    println!("I received this VC info: {:?}", info);

    let data = do_post(info.subject_id.as_str());
    HttpResponse::Ok()
        // .content_type(ContentType::json())
        .insert_header(("Content-Type", "application/ld+json"))
        .keep_alive()
        // .append_header(("Transfer-Encoding", "chunked"))
        .body(data)
}

fn do_post(subject_id: &str) -> String {
    // TODO: generate_vc should take the subject_id and insert that DID
    // into the subject id field when creating the credential. But for now
    // this is hard-coded in the sample credential named:
    // credential_for_did-tz-tz1hne1ao44vqbVTo4ttWjokieJrdEZW9b8C.jsonld

    generate_vc(false, Some(subject_id))
}

fn cli_echo() {
    let mut command = Command::new("echo");
    command.arg("'Hello'");
    // first_command.arg("-version");
    let output = command.execute_output().unwrap();

    // command.stdout(Stdio::piped());
    // command.stderr(Stdio::piped());
    // println!("{}", String::from_utf8(output.stdout).unwrap());
    // println!("{}", String::from_utf8(output.stderr).unwrap());
}

// fn generate_vc_offer() -> String {
//     // For now, return the whole VC in the preview.
//     generate_vc(true, None)
// }

/// Generates a VC (prototype uses const DID and const credential file)
fn generate_vc(is_offer: bool, subject_id: Option<&str>) -> String {
    // Note: we ignore the subject_id for now - just testing with hard-code DID fields.

    let home = std::env::var("HOME").unwrap();
    let command_str = format!("trustchain-cli vc attest --credential_file {}/.trustchain/credentials/credential_for_did-tz-tz1hne1ao44vqbVTo4ttWjokieJrdEZW9b8C.jsonld --did did:ion:test:EiBYdto2LQd_uAj_EXEoxP_KbLmZzwe1E-vXp8ZsMv1Gpg", home);
    let mut iter = command_str.split(" ");
    let mut command = Command::new(iter.next().unwrap());
    for s in iter {
        println!("{}", s);
        command.arg(s);
    }
    println!("{:?}", command);
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    let output = command.execute_output().unwrap();
    println!("{}", String::from_utf8(output.clone().stdout).unwrap());
    println!("{}", String::from_utf8(output.clone().stderr).unwrap());

    let vc_string = String::from_utf8(output.clone().stdout).unwrap();

    if !is_offer {
        return vc_string;
    }

    // {"type":"CredentialOffer","credentialPreview":{"@context":["https://www.w3.org/2018/credentials/v1"],"id":"urn:uuid:6bf9f474-ee23-4bd6-b507-a10acbb45a4a","type":"VerifiableCredential","issuer":"did:web:demo.spruceid.com:2022:06","issuanceDate":"2022-12-20T14:16:30Z","expirationDate":"2023-01-19T14:16:30Z","credentialSubject":{}},"expires":"2022-12-20T14:19:49Z"}
    let mut vc: Map<String, Value> = serde_json::from_str(vc_string.as_str()).unwrap();
    vc.remove("proof");

    // Make our credential offer
    let mut offer: Map<String, Value> = Map::new();

    // Type: credential offer
    offer.insert(
        "type".to_string(),
        Value::String("CredentialOffer".to_string()),
    );

    // Our VC
    offer.insert("credentialPreview".to_string(), Value::Object(vc));

    // 2022-12-20T14:19:49Z
    // time
    offer.insert(
        "expires".to_string(),
        Value::String("2022-12-21T14:19:49Z".to_string()),
    );
    // String::from_utf8(output.stdout).unwrap()

    // String::from_utf8(String::from_utf8(output.clone().stdout)).unwrap()
    String::from_utf8(serde_json::to_string(&offer).unwrap().into_bytes()).unwrap()
}

#[actix_web::main] // or #[tokio::main]
async fn main() -> std::io::Result<()> {
    // env::set_var("RUST_LOG", "actix_web=info");
    // env_logger::init();
    HttpServer::new(|| {
        App::new()
            .service(greet)
            .service(get_vc_offer)
            .service(post_request)
    })
    .bind(("127.0.0.1", 8081))?
    .run()
    .await
}
