use axum::{response::IntoResponse, Json};
use hyper::StatusCode;
use serde_json::json;
use thiserror::Error;
use trustchain_core::{
    commitment::CommitmentError, issuer::IssuerError, resolver::ResolverError,
    verifier::VerifierError,
};
use trustchain_ion::root::TrustchainRootError;

// TODO: refine and add doc comments for error variants
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
    #[error("Trustchain issuer error: {0}")]
    IssuerError(IssuerError),
    #[error("Trustchain root error: {0}")]
    RootError(TrustchainRootError),
    #[error("Credential does not exist.")]
    CredentialDoesNotExist,
    #[error("No issuer available.")]
    NoCredentialIssuer,
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

impl From<IssuerError> for TrustchainHTTPError {
    fn from(err: IssuerError) -> Self {
        TrustchainHTTPError::IssuerError(err)
    }
}

impl From<TrustchainRootError> for TrustchainHTTPError {
    fn from(err: TrustchainRootError) -> Self {
        TrustchainHTTPError::RootError(err)
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
            err @ TrustchainHTTPError::VerifierError(VerifierError::CommitmentFailure(_)) => {
                (StatusCode::OK, err.to_string())
            }
            err @ TrustchainHTTPError::VerifierError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
            }
            err @ TrustchainHTTPError::IssuerError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
            }
            err @ TrustchainHTTPError::CommitmentError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
            }
            err @ TrustchainHTTPError::ResolverError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
            }
            err @ TrustchainHTTPError::CredentialDoesNotExist => {
                (StatusCode::BAD_REQUEST, err.to_string())
            }
            err @ TrustchainHTTPError::NoCredentialIssuer => {
                (StatusCode::BAD_REQUEST, err.to_string())
            }
            err @ TrustchainHTTPError::RootError(_) => (StatusCode::BAD_REQUEST, err.to_string()),
        };
        let body = Json(json!({ "error": err_message }));
        (status, body).into_response()
    }
}
