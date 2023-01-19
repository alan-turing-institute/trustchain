use actix_web::Result as ActixResult;
use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};
use base64::engine::general_purpose;
use base64::write::EncoderWriter;
use image::{DynamicImage, ImageOutputFormat};
use image::{EncodableLayout, Luma};
use qrcode::QrCode;
use serde::{Deserialize, Serialize};
use serde_json::{to_string_pretty, Map, Value};
use ssi::one_or_many::OneOrMany;
use ssi::vc::Credential;
use std::io::Write;
use std::process::{Command, Stdio};
use uuid::Uuid;

/// Server localhost address
// const HOST: &str = "http://127.0.0.1:8081";
/// Android server localhost address
const HOST: &str = "http://10.0.2.2:8081";

/// Example VP request used by demo.spruceid.com
const EXAMPLE_VP_REQUEST: &str = r#"{ "type": "VerifiablePresentationRequest", "query": [ { "type": "QueryByExample", "credentialQuery": { "reason": "Sign in", "example": { "@context": [ "https:\/\/www.w3.org\/2018\/credentials\/v1" ], "type": "VerifiableCredential" } } } ], "challenge": "4f34494e-43d4-4e08-8b72-d634650daf44", "domain": "demo.spruceid.com" }"#;

// Process sketch:
// 1. User visits "credentials/" page and is displayed a QR code of a URI (with UUID) to send GET request to
//    - Post request could contain: Name, DID (optionally), other stuff?
// 2. Within credible app, scan QR code of address which performs GET
// 3. Server receives get request and returns a credential offer with UUID from URI
// 4. Credible receives offer and returns POST with any user info (i.e. the DID)
// 5. Server receives POST data, checks it is valid for UUID and returns a signed credential with offer
// 6. Credible receives response and verifies credential received using the Trustchain server

pub fn image_to_base64_string(image: &DynamicImage) -> String {
    let mut buf = Vec::new();
    {
        let mut writer = EncoderWriter::new(&mut buf, &general_purpose::STANDARD);
        image.write_to(&mut writer, ImageOutputFormat::Png).unwrap();
    }
    std::str::from_utf8(&buf).unwrap().to_string()
}

pub fn str_to_qr_code_html(s: &str) -> String {
    // Make QR code
    let code = QrCode::new(s.as_bytes()).unwrap();

    // Render the bits into an image.
    let image = DynamicImage::ImageLuma8(code.render::<Luma<u8>>().build());
    let image_str = image_to_base64_string(&image);
    let image_str = format!("data:image/png;base64,{}", image_str);
    let html = format!(
        "<!doctype html>
        <html>
            <head>
            <meta charset=utf-8>
            <title>Forms</title>
        </head>
        <body>
            <div>
            <a href={s}>
                <img src={image_str} />
            </div>
        </body>
        </html>"
    );
    html
}

#[derive(Serialize, Deserialize)]
pub struct MyParams {
    name: String,
}

/// Simple handle POST request (see [examples](https://github.com/actix/examples/blob/master/forms/form/src/main.rs))
async fn handle_issuer_post_start(_params: web::Form<MyParams>) -> ActixResult<HttpResponse> {
    // Generate a UUID
    let id = Uuid::new_v4().to_string();

    // Generate a QR code for server address and combination of name and UUID
    let address_str = format!("{HOST}/vc/issuer/{id}");

    // Respond with the QR code as a png embedded in html
    Ok(HttpResponse::Ok()
        .content_type("text/html")
        .body(str_to_qr_code_html(&address_str)))
}

async fn index() -> ActixResult<HttpResponse> {
    Ok(HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(include_str!("../static/front.html")))
}
async fn issuer() -> ActixResult<HttpResponse> {
    Ok(HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(include_str!("../static/issuer.html")))
}

#[get("/hello/{name}")]
async fn greet(name: web::Path<String>) -> impl Responder {
    format!("Hello {name}!")
}

async fn vp_offer_address() -> ActixResult<HttpResponse> {
    // Generate a QR code for server address and combination of name and UUID
    let address_str = format!("{HOST}/vc/verifier");

    // Respond with the QR code as a png embedded in html
    Ok(HttpResponse::Ok()
        .content_type("text/html")
        .body(str_to_qr_code_html(&address_str)))
}

/// API endpoint taking the UUID of a VC. Response is the VC JSON.
// TODO: identify how to handle multiple string variables
#[get("/vc/verifier")]
async fn get_vp_offer() -> impl Responder {
    // Return the presentation request
    EXAMPLE_VP_REQUEST
}

#[post("/vc/verifier")]
async fn post_request_verifier(info: web::Json<Credential>) -> impl Responder {
    println!(
        "RECEIVED CREDENTIAL AT PRESENTATION:\n{}",
        serde_json::to_string_pretty(&info).unwrap().to_string()
    );
    // TODO: check whether a specific response body is required
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body("Received!")
}

fn handle_get_vc(id: &str) -> String {
    generate_vc(true, None, id)
}

/// API endpoint taking the UUID of a VC. Response is the VC JSON.
// TODO: identify how to handle multiple string variables
#[get("/vc/issuer/{id}")]
async fn get_vc_offer(id: web::Path<String>) -> impl Responder {
    handle_get_vc(&id)
}

#[derive(Deserialize, Serialize, Clone, Debug)]
struct VcInfo {
    subject_id: String,
}

#[post("/vc/issuer/{id}")]
async fn post_request(info: web::Json<VcInfo>, id: web::Path<String>) -> impl Responder {
    println!("I received this VC info: {:?}", info);
    let data = handle_post_vc(info.subject_id.as_str(), &id.to_string());
    HttpResponse::Ok()
        .insert_header(("Content-Type", "application/ld+json"))
        .keep_alive()
        // .append_header(("Transfer-Encoding", "chunked"))
        .body(data)
}

fn handle_post_vc(subject_id: &str, credential_id: &str) -> String {
    generate_vc(false, Some(subject_id), credential_id)
}

/// Converts a credential into an offer
fn credential_to_offer(credential: &str) -> String {
    todo!()
}

/// Verifies a received credential
fn verify_vc(credential: &web::Json<Credential>) -> String {
    todo!()
}

/// Generates a VC (prototype uses const DID and const credential file)
fn generate_vc(is_offer: bool, subject_id: Option<&str>, credential_id: &str) -> String {
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

#[actix_web::main] // or #[tokio::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .service(greet)
            .service(get_vc_offer)
            .service(post_request)
            .service(web::resource("/").route(web::get().to(index)))
            .service(web::resource("/issuer").route(web::get().to(issuer)))
            .service(web::resource("/issuer/post1").route(web::post().to(handle_issuer_post_start)))
            .service(web::resource("/verifier").route(web::get().to(vp_offer_address)))
            .service(get_vp_offer)
            .service(post_request_verifier)
    })
    .bind(("127.0.0.1", 8081))?
    .run()
    .await
}
