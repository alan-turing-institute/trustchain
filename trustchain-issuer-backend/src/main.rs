use actix_web::Result as ActixResult;
use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};
use base64::engine::general_purpose;
use base64::write::EncoderWriter;
use execute::Execute;
use image::Luma;
use image::{DynamicImage, ImageOutputFormat};
use qrcode::QrCode;
use serde::{Deserialize, Serialize};
use serde_json::{to_string_pretty, Map, Value};
use std::process::{Command, Stdio};
use uuid::Uuid;

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

#[derive(Serialize, Deserialize)]
pub struct MyParams {
    name: String,
}

/// Simple handle POST request (see [examples](https://github.com/actix/examples/blob/master/forms/form/src/main.rs))
async fn handle_issuer_post_start(_params: web::Form<MyParams>) -> ActixResult<HttpResponse> {
    // Generate a UUID
    let id = Uuid::new_v4().to_string().replace("-", "");

    // Generate a QR code for server address and combination of name and UUID
    let address_str = format!("http://127.0.0.1:8081/vc/{id}");
    // let address_str = format!("http://10.0.2.2:8081/vc/{id}");
    let code = QrCode::new(address_str.as_bytes()).unwrap();

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
            <a href={address_str}>
                <img src={image_str} />
            </div>
        </body>
        </html>"
    );

    // Respond with the QR code as a png embedded in html
    Ok(HttpResponse::Ok().content_type("text/html").body(html))
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

fn handle_get_vc(id: &str) -> String {
    generate_vc(true, None, id)
}

/// API endpoint taking the UUID of a VC. Response is the VC JSON.
// TODO: identify how to handle multiple string variables
#[get("/vc/{id}")]
async fn get_vc_offer(id: web::Path<String>) -> impl Responder {
    handle_get_vc(&id)
}

#[derive(Deserialize, Serialize, Clone, Debug)]
struct VcInfo {
    subject_id: String,
}

#[post("/vc/{id}")]
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
    // TODO: generate_vc should take the subject_id and insert that DID
    // into the subject id field when creating the credential. But for now
    // this is hard-coded in the sample credential named:
    // credential_for_did-tz-tz1hne1ao44vqbVTo4ttWjokieJrdEZW9b8C.jsonld
    generate_vc(false, Some(subject_id), credential_id)
}

/// Generates a VC (prototype uses const DID and const credential file)
fn generate_vc(is_offer: bool, subject_id: Option<&str>, credential_id: &str) -> String {
    // Note: we ignore the subject_id for now - just testing with hard-code DID fields.
    let home = std::env::var("HOME").unwrap();
    // TODO: read credential here, update with UUID:
    //   - Pass into command str?
    //   - Read credential string as bytes from stdin
    let command_str = format!("trustchain-cli vc attest --credential_file {}/.trustchain/credentials/credential_for_did-tz-tz1hne1ao44vqbVTo4ttWjokieJrdEZW9b8C.jsonld --did did:ion:test:EiBYdto2LQd_uAj_EXEoxP_KbLmZzwe1E-vXp8ZsMv1Gpg", home);
    let mut iter = command_str.split(" ");
    let mut command = Command::new(iter.next().unwrap());
    for s in iter {
        println!("{}", s);
        command.arg(s);
    }
    println!("{:?}", command);
    command.stdout(Stdio::piped()).stderr(Stdio::piped());

    let output = command.execute_output().unwrap();
    println!("{}", String::from_utf8(output.clone().stdout).unwrap());
    println!("{}", String::from_utf8(output.clone().stderr).unwrap());

    let vc_string = String::from_utf8(output.clone().stdout).unwrap();

    // Credential offer structure
    // {
    //   "type":"CredentialOffer",
    //   "credentialPreview":{<CREDENTIAL_PREVIEW>},
    //   "expires":"2022-12-20T14:19:49Z"
    // }
    let mut vc: Map<String, Value> = serde_json::from_str(vc_string.as_str()).unwrap();

    if !is_offer {
        let vc_string = serde_json::to_string_pretty(&vc).unwrap();
        println!("CREDENTIAL:\n{}", vc_string);
        return vc_string;
    }

    // Remove proof
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
    println!("OFFER:");
    println!("{}", to_string_pretty(&offer).unwrap());
    String::from_utf8(serde_json::to_string(&offer).unwrap().into_bytes()).unwrap()
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
    })
    .bind(("127.0.0.1", 8081))?
    .run()
    .await
}
