use axum::{response::IntoResponse, Json};
use hyper::StatusCode;
use serde_json::json;
use thiserror::Error;
use trustchain_core::{
    attestor::AttestorError, commitment::CommitmentError, issuer::IssuerError,
    key_manager::KeyManagerError, resolver::ResolverError, vc::CredentialError,
    verifier::VerifierError, vp::PresentationError,
};
use trustchain_ion::root::TrustchainRootError;

use crate::attestation_utils::TrustchainCRError;

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
    #[error("Trustchain presentation error: {0}")]
    PresentationError(PresentationError),
    #[error("Trustchain attestor error: {0}")]
    AttestorError(#[from] AttestorError),
    // TODO: once needed in http propagate
    // #[error("Jose error: {0}")]
    // JoseError(JoseError),
    #[error("Trustchain key manager error: {0}")]
    KeyManagerError(KeyManagerError),
    #[error("Trustchain challenge-response error: {0}")]
    CRError(TrustchainCRError),
    #[error("Credential does not exist.")]
    CredentialDoesNotExist,
    #[error("No issuer available.")]
    NoCredentialIssuer,
    #[error("Wrapped reqwest error: {0}")]
    ReqwestError(reqwest::Error),
    #[error("Failed to verify credential.")]
    FailedToVerifyCredential,
    #[error("Invalid signature.")]
    InvalidSignature,
    #[error("Request does not exist.")]
    RequestDoesNotExist,
    #[error("Could not deserialize data: {0}")]
    FailedToDeserialize(#[from] serde_json::Error),
    #[error("Root event time not configured for verification.")]
    RootEventTimeNotSet,
    #[error("Attestation request failed.")]
    FailedAttestationRequest,
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

impl From<PresentationError> for TrustchainHTTPError {
    fn from(err: PresentationError) -> Self {
        TrustchainHTTPError::PresentationError(err)
    }
}

impl From<KeyManagerError> for TrustchainHTTPError {
    fn from(err: KeyManagerError) -> Self {
        TrustchainHTTPError::KeyManagerError(err)
    }
}

impl From<TrustchainCRError> for TrustchainHTTPError {
    fn from(err: TrustchainCRError) -> Self {
        TrustchainHTTPError::CRError(err)
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
            err @ TrustchainHTTPError::VerifierError(VerifierError::InvalidRoot(_))
            | err @ TrustchainHTTPError::VerifierError(VerifierError::CommitmentFailure(_)) => {
                (StatusCode::OK, err.to_string())
            }
            err @ TrustchainHTTPError::VerifierError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
            }
            err @ TrustchainHTTPError::IssuerError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
            }
            err @ TrustchainHTTPError::AttestorError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
            }
            err @ TrustchainHTTPError::CommitmentError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
            }
            err @ TrustchainHTTPError::ResolverError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
            }
            err @ TrustchainHTTPError::PresentationError(PresentationError::CredentialError(
                CredentialError::VerifierError(VerifierError::CommitmentFailure(_)),
            ))
            | err @ TrustchainHTTPError::PresentationError(PresentationError::CredentialError(
                CredentialError::VerifierError(VerifierError::InvalidRoot(_)),
            )) => (StatusCode::OK, err.to_string()),
            err @ TrustchainHTTPError::PresentationError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
            }
            err @ TrustchainHTTPError::KeyManagerError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
            }
            err @ TrustchainHTTPError::CRError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
            }
            err @ TrustchainHTTPError::CredentialDoesNotExist => {
                (StatusCode::BAD_REQUEST, err.to_string())
            }
            err @ TrustchainHTTPError::NoCredentialIssuer => {
                (StatusCode::BAD_REQUEST, err.to_string())
            }
            TrustchainHTTPError::ReqwestError(err) => (
                err.status().unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                err.to_string(),
            ),
            ref err @ TrustchainHTTPError::RootError(ref variant) => match variant {
                TrustchainRootError::NoUniqueRootEvent(_) => {
                    (StatusCode::BAD_REQUEST, err.to_string())
                }
                TrustchainRootError::InvalidDate(_, _, _) => {
                    (StatusCode::BAD_REQUEST, err.to_string())
                }
                TrustchainRootError::FailedToParseBlockHeight(_) => {
                    (StatusCode::BAD_REQUEST, err.to_string())
                }
                _ => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
            },
            err @ TrustchainHTTPError::FailedToVerifyCredential => {
                (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
            }
            err @ TrustchainHTTPError::InvalidSignature => {
                (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
            }
            err @ TrustchainHTTPError::RequestDoesNotExist => {
                (StatusCode::BAD_REQUEST, err.to_string())
            }
            err @ TrustchainHTTPError::FailedToDeserialize(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
            }
            err @ TrustchainHTTPError::RootEventTimeNotSet => {
                (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
            }
            err @ TrustchainHTTPError::FailedAttestationRequest => {
                (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
            }
        };
        let body = Json(json!({ "error": err_message }));
        (status, body).into_response()
    }
}
