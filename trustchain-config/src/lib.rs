use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::fs;
use toml;

lazy_static! {
    pub static ref TRUSTCHAIN_CONFIG: TrustchainConfig = toml::from_str(
        &fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/trustchain_config.toml"
        ))
        .expect("Error reading trustchain_config.toml")
    )
    .expect("Error parsing trustchain_config.toml");
}

pub fn get_config() -> &'static TRUSTCHAIN_CONFIG {
    &TRUSTCHAIN_CONFIG
}

/// trustchain-core configuration settings
#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct TrustchainConfig {
    pub core: CoreConfig,
    pub ion: IonConfig,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct CoreConfig {
    /// Rust variable for Trustchain data environment variable.
    pub trustchain_data: String,

    /// The value used in a DID document to identify the default Trustchain service endpoint.
    pub trustchain_service_id_value: String,

    /// The value used for identifying a service containing a Trustchain controller proof within a DID document.
    pub trustchain_proof_service_id_value: String,

    /// The value of the type for the service containing a Trustchain controller proof within a DID document.
    pub trustchain_proof_service_type_value: String,

    /// Root event unix time for first Trustchain root on testnet.
    pub root_event_time: u32,

    /// Root event unix time for second Trustchain root on testnet.
    pub root_event_time_2378493: u32,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct IonConfig {
    // MongoDB
    pub mongo_connection_string: String,
    pub mongo_database_ion_testnet_core: String,
    pub mongo_collection_operations: String,
    pub mongo_filter_type: String,
    pub mongo_create_operation: String,
    pub mongo_filter_did_suffix: String,

    // Bitcoin (TESTNET PORT: 18332!)
    pub bitcoin_connection_string: String,
    pub bitcoin_rpc_username: String,
    pub bitcoin_rpc_password: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize() {
        let config_string = "
        [core]
        trustchain_data = \"TRUSTCHAIN_DATA\"
        trustchain_service_id_value = \"TrustchainID\"
        trustchain_proof_service_id_value = \"trustchain-controller-proof\"
        trustchain_proof_service_type_value = \"TrustchainProofService\"
        root_event_time = 1666265405
        root_event_time_2378493 = 1666971942

        [ion]
        mongo_connection_string = \"mongodb://localhost:27017/\"
        mongo_database_ion_testnet_core = \"ion-testnet-core\"
        mongo_collection_operations = \"operations\"
        mongo_filter_type = \"type\"
        mongo_create_operation = \"create\"
        mongo_filter_did_suffix = \"didSuffix\"

        bitcoin_connection_string = \"http://localhost:18332\"
        bitcoin_rpc_username = \"admin\"
        bitcoin_rpc_password = \"lWrkJlpj8SbnNRUJfO6qwIFEWkD+I9kL4REsFyMBlow=\"
        ";

        let config: TrustchainConfig = toml::from_str(config_string).unwrap();

        assert_eq!(
            config,
            TrustchainConfig {
                core: CoreConfig {
                    trustchain_data: "TRUSTCHAIN_DATA".to_string(),
                    trustchain_service_id_value: "TrustchainID".to_string(),
                    trustchain_proof_service_id_value: "trustchain-controller-proof".to_string(),
                    trustchain_proof_service_type_value: "TrustchainProofService".to_string(),
                    root_event_time: 1666265405,
                    root_event_time_2378493: 1666971942
                },
                ion: IonConfig {
                    mongo_connection_string: "mongodb://localhost:27017/".to_string(),
                    mongo_database_ion_testnet_core: "ion-testnet-core".to_string(),
                    mongo_collection_operations: "operations".to_string(),
                    mongo_filter_type: "type".to_string(),
                    mongo_create_operation: "create".to_string(),
                    mongo_filter_did_suffix: "didSuffix".to_string(),
                    bitcoin_connection_string: "http://localhost:18332".to_string(),
                    bitcoin_rpc_username: "admin".to_string(),
                    bitcoin_rpc_password: "lWrkJlpj8SbnNRUJfO6qwIFEWkD+I9kL4REsFyMBlow="
                        .to_string(),
                }
            }
        );
    }
}
