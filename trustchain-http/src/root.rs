use async_trait::async_trait;
use axum::extract::Query;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use chrono::NaiveDate;
use log::debug;
use serde::{Deserialize, Serialize};
use trustchain_ion::root::{root_did_candidates, RootCandidate, TrustchainRootError};

use crate::errors::TrustchainHTTPError;

/// An HTTP API for identifying candidate root DIDs.
#[async_trait]
pub trait TrustchainRootHTTP {
    /// Gets a vector of root DID candidates timestamped a given date.
    async fn root_candidates(date: NaiveDate) -> Result<RootCandidatesResult, TrustchainHTTPError>;
}

/// Type for implementing the TrustchainIssuerHTTP trait that will contain additional handler methods.
pub struct TrustchainRootHTTPHandler {}

#[async_trait]
impl TrustchainRootHTTP for TrustchainRootHTTPHandler {
    async fn root_candidates(date: NaiveDate) -> Result<RootCandidatesResult, TrustchainHTTPError> {
        debug!("Getting root candidates for {0}", date);
        let result = RootCandidatesResult::new(root_did_candidates(date).await?);

        debug!("Got root candidates: {:?}", result);
        Ok(result)
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
    pub async fn get_root_candidates(
        Query(year): Query<RootEventYear>,
        Query(month): Query<RootEventMonth>,
        Query(day): Query<RootEventDay>,
    ) -> impl IntoResponse {
        debug!(
            "Received date for root DID candidates: {:?}-{:?}-{:?}",
            year, month, day
        );

        let date = chrono::NaiveDate::from_ymd_opt(year.year, month.month, day.day);
        if date.is_none() {
            return Err(TrustchainHTTPError::RootCandidatesError(
                TrustchainRootError::InvalidDate(year.year, month.month, day.day),
            ));
        }
        TrustchainRootHTTPHandler::root_candidates(date.unwrap())
            .await
            .map(|vec| (StatusCode::OK, Json(vec)))
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// Type representing the result of converting a `DIDChain` to a chain of DID documents with [W3C](https://w3c-ccg.github.io/did-resolution/#did-resolution-result)
/// data structure.
pub struct RootCandidatesResult {
    root_candidates: Vec<RootCandidate>,
}

impl RootCandidatesResult {
    pub fn new(root_candidates: Vec<RootCandidate>) -> Self {
        Self { root_candidates }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::HTTPConfig, server::TrustchainRouter};
    use axum_test_helper::TestClient;

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
            r#"{"error":"Trustchain root candidates error: Invalid date: 2022-10-40"}"#.to_string()
        );

        // Valid request:
        let uri = "/root?year=2022&month=10&day=20".to_string();
        let response = client.get(&uri).send().await;
        assert_eq!(response.status(), StatusCode::OK);

        let result: RootCandidatesResult = serde_json::from_str(&response.text().await).unwrap();

        assert_eq!(
            result.root_candidates[16].did,
            "did:ion:test:EiCClfEdkTv_aM3UnBBhlOV89LlGhpQAbfeZLFdFxVFkEg"
        );
        assert_eq!(
            result.root_candidates[16].tx_id,
            "9dc43cca950d923442445340c2e30bc57761a62ef3eaf2417ec5c75784ea9c2c"
        );
    }
}
