use hyper::StatusCode;
use thiserror::Error;

// TODO: refine error variants
#[derive(Error, Debug)]
pub enum TrustchainHTTPError {
    #[error("Internal error with status code: {0}")]
    InternalError(StatusCode),
}
