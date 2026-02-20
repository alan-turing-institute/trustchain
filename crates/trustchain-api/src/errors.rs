//! Error type and conversions.
use axum::{Json, response::IntoResponse};
use hyper::StatusCode;
use josekit::JoseError;
use jsonrpsee_types::error::{ErrorCode, ErrorObject, ErrorObjectOwned};
use serde_json::json;
use thiserror::Error;
use trustchain_core::{
    attestor::AttestorError,
    commitment::CommitmentError,
    issuer::IssuerError,
    key_manager::KeyManagerError,
    resolver::ResolverError,
    vc::{CredentialError, DataCredentialError},
    verifier::VerifierError,
    vp::PresentationError,
};
use trustchain_ion::root::TrustchainRootError;

use trustchain_cr::attestation_utils::TrustchainCRError;

/// Trustchain API error type.
// TODO: refine and add doc comments for error variants
#[derive(Error, Debug)]
pub enum TrustchainAPIError {
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
    #[error("Trustchain attestor error: {0}")]
    AttestorError(#[from] AttestorError),
    // TODO: once needed in http propagate
    #[error("Jose error: {0}")]
    JoseError(#[from] JoseError),
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
    #[error("Failed to verify credential: {0}")]
    FailedToVerifyCredential(CredentialError),
    #[error("Failed to verify presentation: {0}")]
    FailedToVerifyPresentation(PresentationError),
    #[error("Failed to verify data credential: {0}")]
    FailedToVerifyDataCredential(DataCredentialError),
    #[error("Invalid signature.")]
    InvalidSignature,
    #[error("Request does not exist.")]
    RequestDoesNotExist,
    #[error("JSON Deserialization Error: {0}.")]
    FailedToDeserialize(#[from] serde_json::Error),
    #[error("JSON Serialization Error: {0}.")]
    FailedToSerialize(serde_json::Error),
    #[error("Root event time not configured for verification.")]
    RootEventTimeNotSet,
    #[error("Attestation request failed.")]
    FailedAttestationRequest,
    #[error("Failed to parse parameters. Error: {0}")]
    ParseError(String),
    #[error("Failed to read file. Error: {0}")]
    FileReadError(String),
}

impl From<ResolverError> for TrustchainAPIError {
    fn from(err: ResolverError) -> Self {
        TrustchainAPIError::ResolverError(err)
    }
}

impl From<CommitmentError> for TrustchainAPIError {
    fn from(err: CommitmentError) -> Self {
        TrustchainAPIError::CommitmentError(err)
    }
}

impl From<VerifierError> for TrustchainAPIError {
    fn from(err: VerifierError) -> Self {
        TrustchainAPIError::VerifierError(err)
    }
}

impl From<IssuerError> for TrustchainAPIError {
    fn from(err: IssuerError) -> Self {
        TrustchainAPIError::IssuerError(err)
    }
}

impl From<TrustchainRootError> for TrustchainAPIError {
    fn from(err: TrustchainRootError) -> Self {
        TrustchainAPIError::RootError(err)
    }
}

impl From<PresentationError> for TrustchainAPIError {
    fn from(err: PresentationError) -> Self {
        TrustchainAPIError::FailedToVerifyPresentation(err)
    }
}

impl From<KeyManagerError> for TrustchainAPIError {
    fn from(err: KeyManagerError) -> Self {
        TrustchainAPIError::KeyManagerError(err)
    }
}

impl From<TrustchainCRError> for TrustchainAPIError {
    fn from(err: TrustchainCRError) -> Self {
        TrustchainAPIError::CRError(err)
    }
}

// Make TrustchainAPIError suitable for axum responses.
//
// See axum IntoRespone example:
// https://github.com/tokio-rs/axum/blob/main/examples/jwt/src/main.rs#L147-L160
impl IntoResponse for TrustchainAPIError {
    fn into_response(self) -> axum::response::Response {
        // TODO: determine correct status codes for errors
        let (status, err_message) = match self {
            err @ TrustchainAPIError::InternalError => {
                (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
            }
            err @ TrustchainAPIError::VerifierError(VerifierError::InvalidRoot(_))
            | err @ TrustchainAPIError::VerifierError(VerifierError::CommitmentFailure(_)) => {
                (StatusCode::OK, err.to_string())
            }
            err @ TrustchainAPIError::VerifierError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
            }
            err @ TrustchainAPIError::IssuerError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
            }
            err @ TrustchainAPIError::AttestorError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
            }
            err @ TrustchainAPIError::CommitmentError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
            }
            err @ TrustchainAPIError::ResolverError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
            }
            err @ TrustchainAPIError::FailedToVerifyPresentation(
                PresentationError::CredentialError(CredentialError::VerifierError(
                    VerifierError::CommitmentFailure(_),
                )),
            )
            | err @ TrustchainAPIError::FailedToVerifyPresentation(
                PresentationError::CredentialError(CredentialError::VerifierError(
                    VerifierError::InvalidRoot(_),
                )),
            ) => (StatusCode::OK, err.to_string()),
            err @ TrustchainAPIError::FailedToVerifyPresentation(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
            }
            err @ TrustchainAPIError::KeyManagerError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
            }
            err @ TrustchainAPIError::JoseError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
            }
            err @ TrustchainAPIError::CRError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
            }
            err @ TrustchainAPIError::CredentialDoesNotExist => {
                (StatusCode::BAD_REQUEST, err.to_string())
            }
            err @ TrustchainAPIError::NoCredentialIssuer => {
                (StatusCode::BAD_REQUEST, err.to_string())
            }
            TrustchainAPIError::ReqwestError(err) => (
                err.status().unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                err.to_string(),
            ),
            ref err @ TrustchainAPIError::RootError(ref variant) => match variant {
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
            err @ TrustchainAPIError::FailedToVerifyCredential(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
            }
            err @ TrustchainAPIError::FailedToVerifyDataCredential(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
            }
            err @ TrustchainAPIError::InvalidSignature => {
                (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
            }
            err @ TrustchainAPIError::RequestDoesNotExist => {
                (StatusCode::BAD_REQUEST, err.to_string())
            }
            err @ TrustchainAPIError::FailedToDeserialize(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
            }
            err @ TrustchainAPIError::FailedToSerialize(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
            }
            err @ TrustchainAPIError::RootEventTimeNotSet => {
                (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
            }
            err @ TrustchainAPIError::FailedAttestationRequest => {
                (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
            }
            err @ TrustchainAPIError::ParseError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
            }
            err @ TrustchainAPIError::FileReadError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
            }
        };
        let body = Json(json!({ "error": err_message }));
        (status, body).into_response()
    }
}

// Make TrustchainAPIError suitable for jsonrpsee responses.
//
// This automatically implements Into<ErrorObjectOwned> on TrustchainAPIError, which is sufficient
// for TrustchainAPIError to implement jsonsonrpsee::IntoResponse, which means this error type is
// suitable for use in the return value of a closure passed to the jsonrpsee functions
// register_method and register_async_method.
impl From<TrustchainAPIError> for ErrorObjectOwned {
    fn from(err: TrustchainAPIError) -> Self {
        // Report the specific error via the message field.
        // TODO: Support error handling on the consumer side by specifying error codes in the
        // range -32000 to -32099 and using the ErrorCode::ServerError(i32) variant.
        // See the JSON RPC spec: https://www.jsonrpc.org/specification#error_object
        match err {
            TrustchainAPIError::InternalError => ErrorObject::from(ErrorCode::InternalError),
            TrustchainAPIError::RequestDoesNotExist => ErrorObject::from(ErrorCode::InvalidRequest),
            ref e @ _ => {
                ErrorObject::owned::<()>(ErrorCode::InternalError.code(), e.to_string(), None)
            }
        }
    }
}
