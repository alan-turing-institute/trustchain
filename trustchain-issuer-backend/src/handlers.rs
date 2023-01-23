use crate::qrcode::str_to_qr_code_html;
use crate::HOST;
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

#[derive(Serialize, Deserialize)]
pub struct MyParams {
    name: String,
}

pub async fn index() -> ActixResult<HttpResponse> {
    Ok(HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(
            std::fs::read_to_string(format!("{}/static/front.html", env!("CARGO_MANIFEST_DIR")))
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
