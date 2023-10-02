use crate::{errors::TrustchainHTTPError, state::AppState};
use axum::{
    response::{IntoResponse, Response},
    Json,
};
use hyper::Body;
use log::info;
use serde_json::Value;
use std::sync::Arc;

/// Receives ION operation POST request and forwards to local ION node.
pub async fn post_operation(
    Json(operation): Json<Value>,
    _app_state: Arc<AppState>,
) -> impl IntoResponse {
    info!("Received ION operation: {}", operation);
    let client = reqwest::Client::new();
    client
        // TODO: Add config for ION URL
        .post("http://localhost:3000/operations")
        .json(&operation)
        .send()
        .await
        .map_err(TrustchainHTTPError::ReqwestError)
        .map(|response| {
            // See example: https://github.com/tokio-rs/axum/blob/8854e660e9ab07404e5bb8e30b92311d3848de05/examples/reqwest-response/src/main.rs
            let mut response_builder = Response::builder().status(response.status());
            *response_builder.headers_mut().unwrap() = response.headers().clone();
            response_builder
                .body(Body::wrap_stream(response.bytes_stream()))
                .unwrap()
        })
}

#[cfg(test)]
mod tests {
    // use super::*;
    // TODO: add test by setting up:
    //   - a mock server as the ION server
    //   - a test server with the `/operations` route
    // And then sending a POST reqwest and testing response
}
