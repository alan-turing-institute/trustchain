//! Middleware for Trustchain HTTP.
use axum::{
    body::Body,
    extract::Path,
    http::{Request, StatusCode},
    middleware::Next,
    response::IntoResponse,
    Json,
};
use did_ion::{
    sidetree::{DIDSuffix, Sidetree},
    ION,
};
use lazy_static::lazy_static;
use serde_json::json;
use trustchain_ion::config::ion_config;
use trustchain_ion::ion::IONTest;

lazy_static! {
    static ref ION_DID_PREFIX: String = format!("did:{}", ION::METHOD);
    static ref ION_DID_TEST_PREFIX: String =
        format!("{}:{}", &*ION_DID_PREFIX, IONTest::NETWORK.unwrap());
}

/// Generates an error message given DID and expected string length.
fn error_message(did: &str, expected_prefix: &str) -> serde_json::Value {
    json!({
        "error":
            format!(
                "DID: {} does not match expected prefix: {}",
                did,
                expected_prefix
            )
    })
}

// See [example](https://github.com/tokio-rs/axum/blob/v0.6.x/examples/consume-body-in-extractor-or-middleware/src/main.rs)
// from axum with middleware that shows how to consume the request body upfront
pub async fn validate_did(
    Path(did): Path<String>,
    request: Request<Body>,
    next: Next<Body>,
) -> impl IntoResponse {
    tracing::info!(did);
    let did_split = did.rsplit_once(':');
    if did_split.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("InvalidDID: {}", did)})),
        ));
    }
    let (did_prefix, ion_did_suffix) = did_split.unwrap();

    // Only validate ION DIDs. Allow others to pass.
    if !did_prefix.ne(&*ION_DID_PREFIX) && !did_prefix.ne(&*ION_DID_TEST_PREFIX) {
        return Ok(next.run(request).await);
    }

    // Validate the DID suffix given established DID method is ION.
    let ion_did_suffix = DIDSuffix(ion_did_suffix.to_string());
    if let Err(err) = ION::validate_did_suffix(&ion_did_suffix) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": err.to_string()})),
        ));
    };

    // Validate the ION network prefix if testnet.
    if ion_config().mongo_database_ion_core.contains("testnet")
        && did_prefix == *ION_DID_TEST_PREFIX
    {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(error_message(&did, &ION_DID_TEST_PREFIX)),
        ));
    }

    // Validate the ION network prefix if mainnet.
    if ion_config().mongo_database_ion_core.contains("mainnet") && did_prefix == *ION_DID_PREFIX {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(error_message(&did, &ION_DID_PREFIX)),
        ));
    }
    Ok(next.run(request).await)
}
