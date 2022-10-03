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

impl Publisher {
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

    pub async fn get(
        &self,
        header_key: &str,
        header_value: &str,
    ) -> Result<String, PublisherError> {
        // TODO: rewrite header handling
        // TODO: rewrite error handling
        match self
            .client
            .get("https://httpbin.org/get?id=123")
            .header(header_key, header_value)
            .send()
            .await
            .expect("msg")
            .text()
            .await
        {
            Ok(x) => Ok(x),
            Err(_) => Err(PublisherError::ConnectionFailure),
        }
    }

    pub async fn post(&self, request: &str) -> Result<String, PublisherError> {
        // TODO: rewrite error handling
        match self
            .client
            .post("http://httpbin.org/post")
            .body(request.to_string())
            .send()
            .await
            .expect("Failed")
            .text()
            .await
        {
            Ok(x) => Ok(x),
            Err(_) => Err(PublisherError::ConnectionFailure),
        }
    }
}

mod tests {
    use super::*;

    #[test]
    fn get() {
        // Make publisher
        let publisher = Publisher::new();

        // GET request
        let response = publisher
            .runtime
            .block_on(publisher.get("key", "application/json"));
        assert!(response.is_ok());
        println!("body = \n{}", response.unwrap());
    }

    #[test]
    fn post() {
        // Make publisher
        let publisher = Publisher::new();

        // POST request
        let example_body = r##"{
            "type": "update",
            "didSuffix": "EiCWPckEQHqdvdMtVCBLgmsHnEWhPnhmvNDB9PLqjj165A",
            "revealValue": "EiDsNzgHxKBxRg_xnhYBLUavgNu-ZzZcww0mnFZ0d3Hsuw"
        }"##;
        let body = example_body;
        let response = publisher.runtime.block_on(publisher.post(body));
        assert!(response.is_ok());
        println!("res = \n{}", response.unwrap());
    }
}
