use async_trait::async_trait;
use axum::extract::Query;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use chrono::NaiveDate;
use log::debug;
use serde::Deserialize;
use trustchain_ion::root::{root_did_candidates, RootCandidate};

use crate::errors::TrustchainHTTPError;

/// An HTTP API for identifying candidate root DIDs.
#[async_trait]
pub trait TrustchainRootHTTP {
    /// Gets a vector of root DID candidates timestamped a given date.
    async fn root_candidates(date: NaiveDate) -> Result<Vec<RootCandidate>, TrustchainHTTPError>;
}

/// Type for implementing the TrustchainIssuerHTTP trait that will contain additional handler methods.
pub struct TrustchainRootHTTPHandler {}

#[async_trait]
impl TrustchainRootHTTP for TrustchainRootHTTPHandler {
    async fn root_candidates(date: NaiveDate) -> Result<Vec<RootCandidate>, TrustchainHTTPError> {
        debug!("Getting root candidates for {0}", date);
        let result = root_did_candidates(date).await?;

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

        // TODO: handle case date is None.
        let date = chrono::NaiveDate::from_ymd_opt(year.year, month.month, day.day).unwrap();

        TrustchainRootHTTPHandler::root_candidates(date)
            .await
            .map(|vec| (StatusCode::OK, Json(vec)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::HTTPConfig, server::TrustchainRouter};
    use axum_test_helper::TestClient;
    use serde_json::json;

    #[tokio::test]
    #[ignore = "requires MongoDB and Bitcoin RPC"]
    async fn test_root_candidates() {
        let app = TrustchainRouter::from(HTTPConfig::default()).into_router();
        let uri = "/root?year=2022&month=10&day=20".to_string();
        let client = TestClient::new(app);
        let response = client.get(&uri).send().await;
        assert_eq!(response.status(), StatusCode::OK);

        // println!("{:?}", json!(response.text().await));
    }
}
