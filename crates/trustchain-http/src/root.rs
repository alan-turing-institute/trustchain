//! Handler and trait for identifying root DID candidates from a naive date.
use crate::state::AppState;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use log::debug;
use serde::Deserialize;
use std::sync::Arc;
use trustchain_api::api::TrustchainRootAPI;
use trustchain_api::TrustchainAPI;
use trustchain_ion::root::RootError;

// Handlers for requests associated with identifying candidate root DIDs. These are thin wrappers
// around `TrustchainRootAPI` to return values implementing `axum::response::IntoResponse`.

/// Handles a GET request for root DID candidates.
pub async fn get_root_candidates(
    Query(year): Query<RootEventYear>,
    Query(month): Query<RootEventMonth>,
    Query(day): Query<RootEventDay>,
    State(app_state): State<Arc<AppState>>,
) -> impl IntoResponse {
    debug!(
        "Received request for root DID candidates on date: {:?}-{:?}-{:?}",
        year, month, day
    );

    let date = match chrono::NaiveDate::from_ymd_opt(year.year, month.month, day.day) {
        Some(d) => d,
        None => return Err(RootError::InvalidDate(year.year, month.month, day.day).into()),
    };
    TrustchainAPI::root_candidates(date, &app_state.root_candidates)
        .await
        .map(|vec| (StatusCode::OK, Json(vec)))
}

/// Handles a GET request for a transaction timestamp.
pub async fn get_block_timestamp(Path(height): Path<String>) -> impl IntoResponse {
    debug!("Received block height for timestamp: {:?}", height.as_str());
    let block_height = height.parse::<u64>();

    if block_height.is_err() {
        return Err(RootError::FailedToParseBlockHeight(height).into());
    }
    TrustchainAPI::block_timestamp(block_height.unwrap())
        .await
        .map(|result| (StatusCode::OK, Json(result)))
}

#[derive(Deserialize, Debug)]
/// Struct for deserializing root event `year` from handler's query param.
pub struct RootEventYear {
    year: i32,
}

#[derive(Deserialize, Debug)]
/// Struct for deserializing root event `month` from handler's query param.
pub struct RootEventMonth {
    month: u32,
}

#[derive(Deserialize, Debug)]
/// Struct for deserializing root event `day` from handler's query param.
pub struct RootEventDay {
    day: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::HTTPConfig, server::TrustchainRouter};
    use axum_test_helper::TestClient;
    use bitcoin::Network;
    use chrono::NaiveDate;
    use itertools::Itertools;
    use trustchain_ion::{
        root::{RootCandidatesResult, TimestampResult},
        utils::BITCOIN_NETWORK,
    };

    #[tokio::test]
    #[ignore = "requires MongoDB and Bitcoin RPC"]
    async fn test_root_candidates() {
        let app = TrustchainRouter::from(HTTPConfig::default()).into_router();
        let client = TestClient::new(app);

        // Invalid date in request:
        let uri = "/root?year=2022&month=10&day=40".to_string();
        let response = client.get(&uri).send().await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response.text().await,
            r#"{"error":"Trustchain root error: Invalid date: 2022-10-40"}"#.to_string()
        );

        // Valid request:
        match BITCOIN_NETWORK
            .as_ref()
            .expect("Integration test requires Bitcoin")
        {
            Network::Testnet => {
                let uri = "/root?year=2022&month=10&day=20".to_string();
                let response = client.get(&uri).send().await;
                assert_eq!(response.status(), StatusCode::OK);

                let result: RootCandidatesResult =
                    serde_json::from_str(&response.text().await).unwrap();

                assert_eq!(result.date, NaiveDate::from_ymd_opt(2022, 10, 20).unwrap());
                let sorted_root_candidates =
                    result.root_candidates.into_iter().sorted().collect_vec();
                assert_eq!(
                    sorted_root_candidates[26].did,
                    "did:ion:test:EiCClfEdkTv_aM3UnBBhlOV89LlGhpQAbfeZLFdFxVFkEg"
                );
                assert_eq!(
                    sorted_root_candidates[26].txid,
                    "9dc43cca950d923442445340c2e30bc57761a62ef3eaf2417ec5c75784ea9c2c"
                );
            }
            Network::Testnet4 => {
                let uri = "/root?year=2025&month=12&day=28".to_string();
                let response = client.get(&uri).send().await;
                assert_eq!(response.status(), StatusCode::OK);

                let result: RootCandidatesResult =
                    serde_json::from_str(&response.text().await).unwrap();

                assert_eq!(result.date, NaiveDate::from_ymd_opt(2025, 12, 28).unwrap());
                let sorted_root_candidates =
                    result.root_candidates.into_iter().sorted().collect_vec();
                assert_eq!(
                    sorted_root_candidates[2].did,
                    "did:ion:test:EiDnaq8k5I4xGy1NjKZkNgcFwNt1Jm6mLm0TVVes7riyMA"
                );
                assert_eq!(
                    sorted_root_candidates[2].txid,
                    "45fd2acb89da0c5c79e59df90c0e3580a515e66bc71b8194e5ee764640e52e57"
                );
            }
            network @ _ => {
                panic!("No test fixtures for network: {:?}", network);
            }
        };
    }

    #[tokio::test]
    #[ignore = "requires MongoDB and Bitcoin RPC"]
    async fn test_block_timestamp() {
        let app = TrustchainRouter::from(HTTPConfig::default()).into_router();
        let client = TestClient::new(app);

        // Invalid block height in request:
        let uri = "/root/timestamp/2377xyz".to_string();
        let response = client.get(&uri).send().await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response.text().await,
            r#"{"error":"Trustchain root error: Failed to parse block height: 2377xyz"}"#
                .to_string()
        );

        // Invalid block height in request:
        let uri = "/root/timestamp/237744522222".to_string();
        let response = client.get(&uri).send().await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(response.text().await.contains("integer out of range"));

        // Valid request:
        let uri = match BITCOIN_NETWORK
            .as_ref()
            .expect("Integration test requires Bitcoin")
        {
            Network::Testnet => "/root/timestamp/2377445".to_string(),
            Network::Testnet4 => "/root/timestamp/115709".to_string(),
            network @ _ => {
                panic!("No test fixtures for network: {:?}", network);
            }
        };
        let response = client.get(&uri).send().await;
        assert_eq!(response.status(), StatusCode::OK);

        let result: TimestampResult = serde_json::from_str(&response.text().await).unwrap();

        let expected_timestamp = match BITCOIN_NETWORK
            .as_ref()
            .expect("Integration test requires Bitcoin")
        {
            Network::Testnet => 1666265405,
            Network::Testnet4 => 1766953540,
            network @ _ => {
                panic!("No test fixtures for network: {:?}", network);
            }
        };
        assert_eq!(result.timestamp, expected_timestamp);
    }
}
