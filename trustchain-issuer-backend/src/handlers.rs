use crate::config::ServerConfig;
use crate::data::TEST_CHAIN;
use crate::qrcode::str_to_qr_code_html;
use crate::vc::generate_vc;
use crate::EXAMPLE_VP_REQUEST;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse};
use axum::Json;
use core::time;
use log::info;
use serde::{Deserialize, Serialize};
use serde_json::to_string_pretty;
use ssi::did::Document;
use ssi::did_resolve::{DocumentMetadata, ResolutionResult};
use ssi::vc::Credential;
use trustchain_core::chain::{Chain, DIDChain};
use trustchain_core::data::{TEST_ROOT_PLUS_2_DOCUMENT, TEST_ROOT_PLUS_2_DOCUMENT_METADATA};
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
pub struct MyParams {
    name: String,
}

pub async fn index() -> Html<String> {
    Html(
        std::fs::read_to_string(format!("{}/static/index.html", env!("CARGO_MANIFEST_DIR")))
            .unwrap(),
    )
}
pub async fn issuer() -> Html<String> {
    Html(
        std::fs::read_to_string(format!("{}/static/issuer.html", env!("CARGO_MANIFEST_DIR")))
            .unwrap(),
    )
}
pub async fn get_verifier_qrcode(State(config): State<ServerConfig>) -> Html<String> {
    // Generate a QR code for server address and combination of name and UUID
    let address_str = format!(
        "http://{}:{}/vc/verifier",
        config.host_reference, config.port
    );

    // Respond with the QR code as a png embedded in html
    Html(str_to_qr_code_html(&address_str, "Verifier"))
}

pub async fn get_issuer_qrcode(State(config): State<ServerConfig>) -> Html<String> {
    // Generate a UUID
    let id = Uuid::new_v4().to_string();

    // Generate a QR code for server address and combination of name and UUID
    let address_str = format!(
        "http://{}:{}/vc/issuer/{id}",
        config.host_reference, config.port
    );

    // Respond with the QR code as a png embedded in html
    Html(str_to_qr_code_html(&address_str, "Issuer"))
}

/// API endpoint taking the UUID of a VC. Response is the VC JSON.
// TODO: identify how to handle multiple string variables
pub async fn get_verifier() -> Html<String> {
    // Return the presentation request
    // (StatusCode::OK, Json(EXAMPLE_VP_REQUEST))
    Html(EXAMPLE_VP_REQUEST.to_string())
}

// #[post("/vc/verifier")]
pub async fn post_verifier(Json(info): Json<Credential>) -> impl IntoResponse {
    info!(
        "Received credential at presentation:\n{}",
        serde_json::to_string_pretty(&info).unwrap()
    );
    // TODO: check whether a specific response body is required
    // See [here](https://w3c-ccg.github.io/vc-api/#prove-presentation)
    (StatusCode::OK, "Received!")
}

/// API endpoint taking the UUID of a VC. Response is the VC JSON.
pub async fn get_issuer(Path(id): Path<String>) -> impl IntoResponse {
    handle_get_vc(&id)
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct VcInfo {
    subject_id: String,
}

pub async fn post_issuer(
    (Path(id), Json(info)): (Path<String>, Json<VcInfo>),
) -> impl IntoResponse {
    info!("Received VC info: {:?}", info);
    let data = handle_post_vc(info.subject_id.as_str(), &id);
    (StatusCode::OK, Json(data))
}

fn handle_get_vc(id: &str) -> String {
    generate_vc(true, None, id)
}

fn handle_post_vc(subject_id: &str, credential_id: &str) -> String {
    generate_vc(false, Some(subject_id), credential_id)
}

// TODO: consider  introducing as a trait in core that DIDChain implements
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

// #[get("/did/{did}")]
pub async fn get_did_resolver(Path(did): Path<String>) -> impl IntoResponse {
    info!("Received DID to resolve: {}", did.as_str());

    // Currently just returns a static string for initial testing
    let doc = serde_json::from_str(TEST_ROOT_PLUS_2_DOCUMENT).unwrap();
    let doc_meta = serde_json::from_str(TEST_ROOT_PLUS_2_DOCUMENT_METADATA).unwrap();

    // Use ResolutionResult struct
    let resolved_json = to_resolution_result(doc, doc_meta);

    // Arbitrary delay for testing
    let delay = time::Duration::from_millis(500);
    std::thread::sleep(delay);
    (
        StatusCode::OK,
        Html(to_string_pretty(&resolved_json).unwrap()),
    )
}
// #[derive(Debug, Serialize, Deserialize)]
// struct DIDChainResolutionResolution {
//     did_chain: Vec<ResolutionResult>,
// }

pub async fn get_did_chain(Path(did): Path<String>) -> impl IntoResponse {
    info!("Received DID to get trustchain: {}", did.as_str());

    // TODO: implement actual verification with trustchain-ion crate
    // let resolver = get_ion_resolver();
    // let verifier = Verifier::new();

    // Currently just returns a static string for initial testing
    let chain: DIDChain = serde_json::from_str(TEST_CHAIN).unwrap();

    // Convert DID chain to vec of ResolutionResults
    let chain_resolution_result_vec = chain
        .to_vec()
        .into_iter()
        .map(|(doc, doc_meta)| to_resolution_result(doc, doc_meta))
        .collect::<Vec<_>>();

    (
        StatusCode::OK,
        Json(to_string_pretty(&chain_resolution_result_vec).unwrap()),
    )
}
