use ssi::vc::{Credential, Presentation};

// TODO: implement in core?
pub struct PresentationRequest;

// TODO: implement in core?
/// An error type for presentation failures
pub enum PresentationError {
    FailedToVerify,
    // TODO: add other variants
}

/// An API for a Trustchain verifier server.
pub trait TrustchainVerifierHTTP {
    /// Constructs a presentation request (given some `presentiation_id`) to send to a credential holder from request wallet by ID
    fn generate_presentation_request(presentation_id: &str) -> PresentationRequest;
    /// Verifies verifiable presentation
    fn verify_presentation(presentation: &Presentation) -> Result<(), PresentationError>;
    /// Verifies verifiable credential
    fn verify_credential(credential: &Credential) -> Result<(), PresentationError>;
}

pub struct TrustchainVerifierHTTPHandler;

impl TrustchainVerifierHTTP for TrustchainVerifierHTTPHandler {
    fn generate_presentation_request(presentation_id: &str) -> PresentationRequest {
        todo!()
    }

    fn verify_presentation(presentation: &Presentation) -> Result<(), PresentationError> {
        todo!()
    }

    fn verify_credential(credential: &Credential) -> Result<(), PresentationError> {
        todo!()
    }
}

// // TODO: integrate verifier-related handlers from current handlers module
// //
// /// API endpoint taking the UUID of a VC. Response is the VC JSON.
// // TODO: identify how to handle multiple string variables
// pub async fn get_verifier() -> Html<String> {
//     // Return the presentation request
//     // (StatusCode::OK, Json(EXAMPLE_VP_REQUEST))
//     Html(EXAMPLE_VP_REQUEST.to_string())
// }

// // #[post("/vc/verifier")]
// pub async fn post_verifier(Json(info): Json<Credential>) -> impl IntoResponse {
//     info!(
//         "Received credential at presentation:\n{}",
//         serde_json::to_string_pretty(&info).unwrap()
//     );
//     // TODO: check whether a specific response body is required
//     // See [here](https://w3c-ccg.github.io/vc-api/#prove-presentation)
//     (StatusCode::OK, "Received!")
// }
