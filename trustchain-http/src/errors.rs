use axum::{
    response::{Html, IntoResponse},
    Json,
};
use hyper::StatusCode;
use serde_json::json;
use thiserror::Error;
use trustchain_core::{
    commitment::CommitmentError, resolver::ResolverError, verifier::VerifierError,
};

// TODO: refine error variants
#[derive(Error, Debug)]
pub enum TrustchainHTTPError {
    #[error("Internal error.")]
    InternalError,
    #[error("Trustchain Verifier error: {0}")]
    VerifierError(VerifierError),
    #[error("Trustchain Commitment error: {0}")]
    CommitmentError(CommitmentError),
    #[error("Trustchain Resolver error: {0}")]
    ResolverError(ResolverError),
}

impl From<ResolverError> for TrustchainHTTPError {
    fn from(err: ResolverError) -> Self {
        TrustchainHTTPError::ResolverError(err)
    }
}

impl From<CommitmentError> for TrustchainHTTPError {
    fn from(err: CommitmentError) -> Self {
        TrustchainHTTPError::CommitmentError(err)
    }
}

impl From<VerifierError> for TrustchainHTTPError {
    fn from(err: VerifierError) -> Self {
        TrustchainHTTPError::VerifierError(err)
    }
}

// See axum IntoRespone example:
// https://github.com/tokio-rs/axum/blob/main/examples/jwt/src/main.rs#L147-L160

impl IntoResponse for TrustchainHTTPError {
    fn into_response(self) -> axum::response::Response {
        // TODO: determine correct status codes for errors
        let (status, err_message) = match self {
            err @ TrustchainHTTPError::InternalError => {
                (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
            }
            err @ TrustchainHTTPError::VerifierError(VerifierError::InvalidRoot(_)) => {
                (StatusCode::OK, err.to_string())
            }
            err @ TrustchainHTTPError::VerifierError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
            }
            err @ TrustchainHTTPError::CommitmentError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
            }
            err @ TrustchainHTTPError::ResolverError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
            }
        };
        let body = Json(json!({ "error": err_message }));
        (status, body).into_response()
    }
}
