use crate::state::AppState;
use async_trait::async_trait;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use chrono::NaiveDate;
use log::debug;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use trustchain_core::verifier::Timestamp;
use trustchain_ion::config::IONConfig;
use trustchain_ion::root::{root_did_candidates, RootCandidate, TrustchainRootError};
use trustchain_ion::utils::time_at_block_height;

use crate::errors::TrustchainHTTPError;

/// An HTTP API for identifying candidate root DIDs.
#[async_trait]
pub trait TrustchainRootHTTP {
    /// Gets a vector of root DID candidates timestamped on a given date.
    async fn root_candidates(
        date: NaiveDate,
        root_candidates: &RwLock<HashMap<NaiveDate, RootCandidatesResult>>,
        config: &IONConfig,
    ) -> Result<RootCandidatesResult, TrustchainHTTPError>;
    /// Gets a unix timestamp for a given Bitcoin transaction ID.
    async fn block_timestamp(
        height: u64,
        config: &IONConfig,
    ) -> Result<TimestampResult, TrustchainHTTPError>;
}

/// Type for implementing the TrustchainIssuerHTTP trait that will contain additional handler methods.
pub struct TrustchainRootHTTPHandler {}

#[async_trait]
impl TrustchainRootHTTP for TrustchainRootHTTPHandler {
    async fn root_candidates(
        date: NaiveDate,
        root_candidates: &RwLock<HashMap<NaiveDate, RootCandidatesResult>>,
        config: &IONConfig,
    ) -> Result<RootCandidatesResult, TrustchainHTTPError> {
        debug!("Getting root candidates for {0}", date);
        {
            let read_guard = root_candidates.read().unwrap();
            // Return the cached vector of root DID candidates, if available.
            if read_guard.contains_key(&date) {
                return Ok(read_guard.get(&date).cloned().unwrap());
            }
        }
        let result = RootCandidatesResult::new(date, root_did_candidates(date, config).await?);
        debug!("Got root candidates: {:?}", &result);

        // Add the result to the cache.
        root_candidates
            .write()
            .unwrap()
            .insert(date, result.clone());
        Ok(result)
    }

    async fn block_timestamp(
        height: u64,
        config: &IONConfig,
    ) -> Result<TimestampResult, TrustchainHTTPError> {
        debug!("Getting unix timestamp for block height: {0}", height);

        let timestamp = time_at_block_height(height, None, config)
            .map_err(|err| TrustchainRootError::FailedToParseBlockHeight(err.to_string()))?;
        debug!("Got block timestamp: {:?}", &timestamp);
        Ok(TimestampResult { timestamp })
    }
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

impl TrustchainRootHTTPHandler {
    /// Handles a GET request for root DID candidates.
    pub async fn get_root_candidates(
        Query(year): Query<RootEventYear>,
        Query(month): Query<RootEventMonth>,
        Query(day): Query<RootEventDay>,
        State(app_state): State<Arc<AppState>>,
    ) -> impl IntoResponse {
        debug!(
            "Received date for root DID candidates: {:?}-{:?}-{:?}",
            year, month, day
        );

        let date = chrono::NaiveDate::from_ymd_opt(year.year, month.month, day.day);
        if date.is_none() {
            return Err(TrustchainHTTPError::RootError(
                TrustchainRootError::InvalidDate(year.year, month.month, day.day),
            ));
        }
        TrustchainRootHTTPHandler::root_candidates(
            date.unwrap(),
            &app_state.root_candidates,
            &app_state.config.ion_config,
        )
        .await
        .map(|vec| (StatusCode::OK, Json(vec)))
    }

    /// Handles a GET request for a transaction timestamp.
    pub async fn get_block_timestamp(
        Path(height): Path<String>,
        State(app_state): State<Arc<AppState>>,
    ) -> impl IntoResponse {
        debug!("Received block height for timestamp: {:?}", height.as_str());
        let block_height = height.parse::<u64>();

        if block_height.is_err() {
            return Err(TrustchainHTTPError::RootError(
                TrustchainRootError::FailedToParseBlockHeight(height),
            ));
        }

        TrustchainRootHTTPHandler::block_timestamp(
            block_height.unwrap(),
            &app_state.config.ion_config,
        )
        .await
        .map(|result| (StatusCode::OK, Json(result)))
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
/// Serializable type representing the result of a request for root DID candidates on a given date.
pub struct RootCandidatesResult {
    date: NaiveDate,
    root_candidates: Vec<RootCandidate>,
}

impl RootCandidatesResult {
    pub fn new(date: NaiveDate, root_candidates: Vec<RootCandidate>) -> Self {
        Self {
            date,
            root_candidates,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
/// Serializable type representing the result of a request for root DID candidates on a given date.
pub struct TimestampResult {
    timestamp: Timestamp,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::http_config_owned, server::TrustchainRouter};
    use axum_test_helper::TestClient;
    use trustchain_core::utils::init;

    #[tokio::test]
    #[ignore = "requires MongoDB and Bitcoin RPC"]
    async fn test_root_candidates() {
        init();
        let app = TrustchainRouter::from(http_config_owned()).into_router();
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
        let uri = "/root?year=2022&month=10&day=20".to_string();
        let response = client.get(&uri).send().await;
        assert_eq!(response.status(), StatusCode::OK);

        let result: RootCandidatesResult = serde_json::from_str(&response.text().await).unwrap();

        assert_eq!(result.date, NaiveDate::from_ymd_opt(2022, 10, 20).unwrap());

        assert_eq!(
            result.root_candidates[16].did,
            "did:ion:test:EiCClfEdkTv_aM3UnBBhlOV89LlGhpQAbfeZLFdFxVFkEg"
        );
        assert_eq!(
            result.root_candidates[16].txid,
            "9dc43cca950d923442445340c2e30bc57761a62ef3eaf2417ec5c75784ea9c2c"
        );
    }

    #[tokio::test]
    #[ignore = "requires MongoDB and Bitcoin RPC"]
    async fn test_block_timestamp() {
        init();
        let app = TrustchainRouter::from(http_config_owned()).into_router();
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
        let uri = "/root/timestamp/2377445".to_string();
        let response = client.get(&uri).send().await;
        assert_eq!(response.status(), StatusCode::OK);

        let result: TimestampResult = serde_json::from_str(&response.text().await).unwrap();

        assert_eq!(result.timestamp, 1666265405);
    }
}
