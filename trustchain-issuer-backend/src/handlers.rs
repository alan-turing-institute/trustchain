use crate::qrcode::str_to_qr_code_html;
use crate::vc::generate_vc;
use crate::{EXAMPLE_VP_REQUEST, HOST};
use actix_web::Result as ActixResult;
use actix_web::{get, post, web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use ssi::vc::Credential;
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
pub struct MyParams {
    name: String,
}

pub async fn index() -> ActixResult<HttpResponse> {
    Ok(HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(
            std::fs::read_to_string(format!("{}/static/index.html", env!("CARGO_MANIFEST_DIR")))
                .unwrap(),
        ))
}
pub async fn issuer() -> ActixResult<HttpResponse> {
    Ok(HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(
            std::fs::read_to_string(format!("{}/static/issuer.html", env!("CARGO_MANIFEST_DIR")))
                .unwrap(),
        ))
}

pub async fn vp_offer_address() -> ActixResult<HttpResponse> {
    // Generate a QR code for server address and combination of name and UUID
    let address_str = format!("{HOST}/vc/verifier");

    // Respond with the QR code as a png embedded in html
    Ok(HttpResponse::Ok()
        .content_type("text/html")
        .body(str_to_qr_code_html(&address_str)))
}

/// Simple handle POST request (see [examples](https://github.com/actix/examples/blob/master/forms/form/src/main.rs))
pub async fn handle_issuer_post_start(_params: web::Form<MyParams>) -> ActixResult<HttpResponse> {
    // Generate a UUID
    let id = Uuid::new_v4().to_string();

    // Generate a QR code for server address and combination of name and UUID
    let address_str = format!("{HOST}/vc/issuer/{id}");

    // Respond with the QR code as a png embedded in html
    Ok(HttpResponse::Ok()
        .content_type("text/html")
        .body(str_to_qr_code_html(&address_str)))
}

#[get("/hello/{name}")]
async fn greet(name: web::Path<String>) -> impl Responder {
    format!("Hello {name}!")
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
    // See [here](https://w3c-ccg.github.io/vc-api/#prove-presentation)
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
