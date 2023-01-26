use crate::data::TEST_CHAIN;
use crate::qrcode::str_to_qr_code_html;
use crate::vc::generate_vc;
use crate::{EXAMPLE_VP_REQUEST, HOST};
use actix_web::Result as ActixResult;
use actix_web::{get, post, web, HttpResponse, Responder};
use log::info;
use serde::{Deserialize, Serialize};
use serde_json::to_string_pretty;
use ssi::did::Document;
use ssi::did_resolve::{DocumentMetadata, ResolutionResult};
use ssi::vc::Credential;
use trustchain_core::chain::DIDChain;
use trustchain_core::data::{TEST_ROOT_PLUS_2_DOCUMENT, TEST_ROOT_PLUS_2_DOCUMENT_METADATA};
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

pub async fn get_verifier_qrcode() -> ActixResult<HttpResponse> {
    // Generate a QR code for server address and combination of name and UUID
    let address_str = format!("{HOST}/vc/verifier");

    // Respond with the QR code as a png embedded in html
    Ok(HttpResponse::Ok()
        .content_type("text/html")
        .body(str_to_qr_code_html(&address_str, "Verifier")))
}

/// Simple handle POST request (see [examples](https://github.com/actix/examples/blob/master/forms/form/src/main.rs))
pub async fn get_issuer_qrcode(_params: web::Form<MyParams>) -> ActixResult<HttpResponse> {
    // Generate a UUID
    let id = Uuid::new_v4().to_string();

    // Generate a QR code for server address and combination of name and UUID
    let address_str = format!("{HOST}/vc/issuer/{id}");

    // Respond with the QR code as a png embedded in html
    Ok(HttpResponse::Ok()
        .content_type("text/html")
        .body(str_to_qr_code_html(&address_str, "Issuer")))
}

/// API endpoint taking the UUID of a VC. Response is the VC JSON.
// TODO: identify how to handle multiple string variables
#[get("/vc/verifier")]
async fn get_verifier() -> impl Responder {
    // Return the presentation request
    EXAMPLE_VP_REQUEST
}

#[post("/vc/verifier")]
async fn post_verifier(info: web::Json<Credential>) -> impl Responder {
    println!(
        "RECEIVED CREDENTIAL AT PRESENTATION:\n{}",
        serde_json::to_string_pretty(&info).unwrap()
    );
    // TODO: check whether a specific response body is required
    // See [here](https://w3c-ccg.github.io/vc-api/#prove-presentation)
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body("Received!")
}

/// API endpoint taking the UUID of a VC. Response is the VC JSON.
#[get("/vc/issuer/{id}")]
async fn get_issuer(id: web::Path<String>) -> impl Responder {
    handle_get_vc(&id)
}

#[derive(Deserialize, Serialize, Clone, Debug)]
struct VcInfo {
    subject_id: String,
}

#[post("/vc/issuer/{id}")]
async fn post_issuer(info: web::Json<VcInfo>, id: web::Path<String>) -> impl Responder {
    println!("I received this VC info: {:?}", info);
    let data = handle_post_vc(info.subject_id.as_str(), &id.to_string());
    HttpResponse::Ok()
        .insert_header(("Content-Type", "application/ld+json"))
        .keep_alive()
        // .append_header(("Transfer-Encoding", "chunked"))
        .body(data)
}

fn handle_get_vc(id: &str) -> String {
    generate_vc(true, None, id)
}

fn handle_post_vc(subject_id: &str, credential_id: &str) -> String {
    generate_vc(false, Some(subject_id), credential_id)
}

fn to_resolution_result(doc: Document, doc_meta: DocumentMetadata) -> ResolutionResult {
    ResolutionResult {
        context: Some(serde_json::Value::String(
            "https://w3id.org/did-resolution/v1".to_string(),
        )),
        did_document: Some(doc),
        did_resolution_metadata: None,
        did_document_metadata: Some(doc_meta),
        property_set: None,
    }
}

#[get("/did/{did}")]
async fn get_did_resolver(did: web::Path<String>) -> impl Responder {
    info!("Received DID to resolve: {}", did.as_str());

    // Currently just returns a static string for initial testing
    let doc = serde_json::from_str(TEST_ROOT_PLUS_2_DOCUMENT).unwrap();
    let doc_meta = serde_json::from_str(TEST_ROOT_PLUS_2_DOCUMENT_METADATA).unwrap();

    // Use ResolutionResult struct
    let resolved_json = to_resolution_result(doc, doc_meta);

    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(to_string_pretty(&resolved_json).unwrap())
}

#[get("/did/chain/{did}")]
async fn get_did_chain(did: web::Path<String>) -> impl Responder {
    info!("Received DID to verify: {}", did.as_str());

    // TODO: implement actual verification with trustchain-ion crate
    // let resolver = get_ion_resolver();
    // let verifier = Verifier::new();

    // Currently just returns a static string for initial testing
    let chain: DIDChain = serde_json::from_str(TEST_CHAIN).unwrap();

    // Convert DID chain to vec of ResolutionResults
    let chain_json = to_string_pretty(&chain).unwrap();
    // let chain_json = to_string_pretty(&chain.to_vec()).unwrap();

    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(chain_json)
}
