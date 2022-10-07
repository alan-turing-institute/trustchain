use reqwest::Client;
use thiserror::Error;
use tokio::runtime::Runtime;

/// An error relating to Trustchain publisher.
#[derive(Error, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PublisherError {
    /// Controller is already present in DID document.
    #[error("Failed to contact client.")]
    ConnectionFailure,
}

/// Struct for performing publishing to a http_client.
pub struct Publisher {
    /// Runtime for calling async functions.
    pub runtime: Runtime,

    /// Client for performing publishing requests
    pub client: Client,
}

/// Converts from reqwest error type into Trustchain PublisherError.
impl From<reqwest::Error> for PublisherError {
    // TODO: consider how to map different reqwest error variants.
    fn from(_error: reqwest::Error) -> Self {
        PublisherError::ConnectionFailure
    }
}

impl Publisher {
    /// Creates a new Publisher struct.
    pub fn new() -> Self {
        // Make an async runtime
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();

        // Make reqwest client
        let client = Client::new();

        Self { runtime, client }
    }

    /// Performs an HTTP get request from passed header_key and header_value.
    pub async fn get(
        &self,
        url: &str,
        header_key: &str,
        header_value: &str,
    ) -> Result<String, PublisherError> {
        // TODO: rewrite header handling
        self.client
            .get(url)
            .header(header_key, header_value)
            .send()
            .await?
            .text()
            .await
            .map_err(|e| e.into())
    }

    /// Performs an HTTP POST request from passed body.
    pub async fn post(&self, url: &str, body: &str) -> Result<String, PublisherError> {
        self.client
            .post(url)
            .body(body.to_string())
            .send()
            .await?
            .text()
            .await
            .map_err(|e| e.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get() {
        // Make publisher
        let publisher = Publisher::new();

        // Test url
        let url = "https://httpbin.org/get?id=123";

        // GET request
        let response = publisher
            .runtime
            .block_on(publisher.get(url, "key", "application/json"));
        assert!(response.is_ok());
        println!("body = \n{}", response.unwrap());
    }

    #[test]
    fn post() {
        // Make publisher
        let publisher = Publisher::new();

        // Test url
        let url = "http://httpbin.org/post";

        // POST request
        let example_body = r##"{
            "type": "update",
            "didSuffix": "EiCWPckEQHqdvdMtVCBLgmsHnEWhPnhmvNDB9PLqjj165A",
            "revealValue": "EiDsNzgHxKBxRg_xnhYBLUavgNu-ZzZcww0mnFZ0d3Hsuw"
        }"##;
        let response = publisher
            .runtime
            .block_on(publisher.post(url, example_body));
        assert!(response.is_ok());
        println!("res = \n{}", response.unwrap());
    }

    #[test]
    #[should_panic]
    fn get_fail() {
        todo!()
    }

    #[test]
    #[should_panic]
    fn post_fail() {
        todo!()
    }
}
