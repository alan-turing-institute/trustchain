use std::path::{Path, PathBuf};

use ssi::jwk::JWK;
use trustchain_core::TRUSTCHAIN_DATA;

use crate::challenge_response::TrustchainCRError;

/// Returns unique path name for a specific attestation request derived from public key for the interaction.
pub fn attestation_request_path(key: &JWK) -> Result<PathBuf, TrustchainCRError> {
    // Root path in TRUSTCHAIN_DATA
    let path: String =
        std::env::var(TRUSTCHAIN_DATA).map_err(|_| TrustchainCRError::FailedAttestationRequest)?;
    let key_id = key
        .thumbprint()
        .map_err(|_| TrustchainCRError::MissingJWK)?; // Use hash of temp_pub_key
    Ok(Path::new(path.as_str())
        .join("attestation_requests")
        .join(key_id))
}
