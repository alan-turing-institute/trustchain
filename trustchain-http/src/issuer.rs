use crate::config::ServerConfig;
use crate::data::TEST_CHAIN;
use crate::qrcode::str_to_qr_code_html;
use crate::resolver::DIDChainResolutionResult;
use crate::resolver::TrustchainHTTPHandler;
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

// TODO: implement with data required for a valid credential offer
/// A type for describing credential offers.
pub struct CredentialOffer;

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct VcInfo {
    subject_id: String,
}

/// An API for a Trustchain verifier server.
pub trait TrustchainIssuerHTTP {
    // pub trait TrustchainIssuerHTTP : TrustchainHTTP + TrustchainDIDCLI + TrustchainVCCLI {
    /// Issues an offer for a verifiable credential
    // TODO: should this be a String or its own type (e.g. `CredentialOffer`)
    fn generate_credential_offer(template: &Credential, credential_id: &str) -> CredentialOffer;
    /// Issues a verfiable credential (should it return `Credential` or `String`)
    fn issue_credential(template: &Credential, subject_id: &str, credential_id: &str)
        -> Credential;
}

/// Type for implementing the TrustchainIssuerHTTP trait that will contain additional handler methods.
pub struct TrustchainIssuerHTTPHandler;

impl TrustchainIssuerHTTP for TrustchainIssuerHTTPHandler {
    fn generate_credential_offer(template: &Credential, credential_id: &str) -> CredentialOffer {
        todo!()
    }

    fn issue_credential(
        template: &Credential,
        subject_id: &str,
        credential_id: &str,
    ) -> Credential {
        todo!()
    }
}

impl TrustchainIssuerHTTPHandler {
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
    pub async fn get_issuer(Path(id): Path<String>) -> impl IntoResponse {
        Self::handle_get_vc(&id)
    }

    pub async fn post_issuer(
        (Path(id), Json(info)): (Path<String>, Json<VcInfo>),
    ) -> impl IntoResponse {
        info!("Received VC info: {:?}", info);
        let data = Self::handle_post_vc(info.subject_id.as_str(), &id);
        (StatusCode::OK, Json(data))
    }

    fn handle_get_vc(id: &str) -> String {
        generate_vc(true, None, id)
    }

    fn handle_post_vc(subject_id: &str, credential_id: &str) -> String {
        generate_vc(false, Some(subject_id), credential_id)
    }
}

// TODO: integrate issuer-related handlers from current handlers module
//
// pub async fn index() -> Html<String> {
//     Html(
//         std::fs::read_to_string(format!("{}/static/index.html", env!("CARGO_MANIFEST_DIR")))
//             .unwrap(),
//     )
// }
// pub async fn issuer() -> Html<String> {
//     Html(
//         std::fs::read_to_string(format!("{}/static/issuer.html", env!("CARGO_MANIFEST_DIR")))
//             .unwrap(),
//     )
// }

// #[cfg(test)]
// mod tests {}
