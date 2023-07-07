use axum::{
    body::Body,
    extract::Path,
    http::{Request, StatusCode},
    middleware::Next,
    response::IntoResponse,
    Json,
};
use serde_json::json;
use trustchain_ion::config::ion_config;

// See example from axum: https://github.com/tokio-rs/axum/blob/v0.6.x/examples/consume-body-in-extractor-or-middleware/src/main.rs
// middleware that shows how to consume the request body upfront
// TODO: refactor using [did-ion method](https://docs.rs/did-ion/latest/did_ion/sidetree/trait.Sidetree.html#method.validate_did_suffix)
pub async fn validate_did(
    Path(did): Path<String>,
    request: Request<Body>,
    next: Next<Body>,
) -> Result<impl IntoResponse, impl IntoResponse> {
    tracing::info!(did);
    // Validate length is 59 (testnet) or 54 (mainnet)
    if ion_config().mongo_database_ion_core.contains("testnet") && did.len() != 59 {
        let message = json!({
            "error":
                format!(
                    "DID: {} is incorrect length {}. Should be length 59.",
                    did,
                    did.len()
                )
        });
        return Err((StatusCode::BAD_REQUEST, Json(message)));
    } else if ion_config().mongo_database_ion_core.contains("mainnet") && did.len() != 54 {
        let message = json!({
            "error":
                format!(
                    "DID: {} is incorrect length {}. Should be length 54.",
                    did,
                    did.len()
                )
        });
        return Err((StatusCode::BAD_REQUEST, Json(message)));
    }
    Ok(next.run(request).await)
}
