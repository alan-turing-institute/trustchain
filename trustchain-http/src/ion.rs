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
    app_state: Arc<AppState>,
) -> impl IntoResponse {
    info!("Received ION operation: {}", operation);
    let client = reqwest::Client::new();
    let address = format!(
        "http://{}:{}/operations",
        app_state.config.ion_host, app_state.config.ion_port
    );
    client
        // TODO: Add config for ION URL
        .post(address)
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
    use super::*;
    use crate::{config::HTTPConfig, server::TrustchainRouter};
    use axum::{response::Html, routing::post, Router};
    use hyper::{Server, StatusCode};
    use std::{collections::HashMap, net::TcpListener};
    use tower::make::Shared;

    async fn mock_post_operation_handler(Json(json): Json<Value>) -> impl IntoResponse {
        Html(format!("Response: {}", json))
    }

    #[tokio::test]
    async fn test_post_operation() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("Could not bind ephemeral socket");
        let trustchain_addr = listener.local_addr().unwrap();
        let trustchain_port = trustchain_addr.port();
        let ion_listener =
            TcpListener::bind("127.0.0.1:0").expect("Could not bind ephemeral socket");
        let ion_addr = ion_listener.local_addr().unwrap();
        let ion_port = ion_addr.port();
        let http_config = HTTPConfig {
            port: trustchain_port,
            ion_port,
            ..Default::default()
        };
        assert_eq!(
            http_config.host.to_string(),
            trustchain_addr.ip().to_string()
        );

        // Run server
        tokio::spawn(async move {
            let trustchain_server = Server::from_tcp(listener).unwrap().serve(Shared::new(
                TrustchainRouter::from(http_config).into_router(),
            ));
            trustchain_server.await.expect("server error");
        });

        // Run mock ION server
        tokio::spawn(async move {
            let ion_server = Server::from_tcp(ion_listener).unwrap().serve(Shared::new(
                Router::new().route("/operations", post(mock_post_operation_handler)),
            ));
            ion_server.await.expect("server error");
        });

        // Send POST request to server
        let client = reqwest::Client::new();
        let addr = format!("http://127.0.0.1:{trustchain_port}/operations");
        let map: HashMap<String, String> = serde_json::from_str(r#"{"key": "value"}"#).unwrap();
        let response = client.post(&addr).json(&map).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            r#"Response: {"key":"value"}"#,
            response.text().await.unwrap()
        );
    }
}
