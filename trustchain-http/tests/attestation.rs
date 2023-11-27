use axum::http::request;
use rand::rngs::mock;
use trustchain_core::verifier::Verifier;
use trustchain_core::TRUSTCHAIN_DATA;
use trustchain_http::attestation_utils::{ElementwiseSerializeDeserialize, IdentityCRInitiation};
use trustchain_http::requester::initiate_identity_challenge;
/// Integration test for attestation challenge-response process.
use trustchain_ion::{get_ion_resolver, verifier::IONVerifier};

// The root event time of DID documents used in integration test below.
const ROOT_EVENT_TIME_1: u64 = 1666265405;

use hyper::Server;
use mockall::automock;
use std::fs;
use std::sync::Once;
use std::{net::TcpListener, path::PathBuf};
use tower::make::Shared;
use trustchain_core::utils::init;
use trustchain_http::{config::HTTPConfig, server::TrustchainRouter};

#[automock]
pub trait AttestationUtils {
    fn attestation_request_path(&self) -> String;
}
// TODO: fix so can be used for all HTTP tests
/// Init for HTTP crate
// static INIT_HTTP: Once = Once::new();
// lazy_static! {
//     static ref HANDLE =
// }
// pub fn init_http() {
//     INIT_HTTP.call_once(|| {
//         init();
//         let listener =
//             TcpListener::bind("127.0.0.1:8082").expect("Could not bind ephemeral socket");
//         let addr = listener.local_addr().unwrap();
//         let port = addr.port();
//         let http_config = HTTPConfig {
//             port,
//             server_did: Some(
//                 "did:ion:test:EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A".to_string(),
//             ),
//             root_event_time: Some(ROOT_EVENT_TIME_1),
//             ..Default::default()
//         };
//         // Run server
//         tokio::spawn(async move {
//             let server = Server::from_tcp(listener).unwrap().serve(Shared::new(
//                 TrustchainRouter::from(http_config).into_router(),
//             ));
//             server.await.expect("server error");
//         });
//     });
// }

#[tokio::test]
#[ignore]
async fn attestation_challenge_response() {
    // init_http();
    init();
    // |------------| requester |------------|
    // Use ROOT_PLUS_1 as attestor. Run server on localhost:8081.
    let attestor_did = "did:ion:test:EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A";
    // let attestor_did = "did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q";
    let resolver = get_ion_resolver("http://localhost:8081/");
    let verifier = IONVerifier::new(resolver);
    let resolver = verifier.resolver();
    // Verify the attestor did to make sure we can trust the endpoint.
    let result = verifier.verify(attestor_did, ROOT_EVENT_TIME_1).await;
    assert!(result.is_ok());
    // Resolve did document.
    let result = resolver.resolve_as_result(attestor_did).await;
    assert!(result.is_ok());
    // Get services from did document.
    let (_, doc, _) = result.unwrap();
    let doc = doc.unwrap();
    let services = doc.service.unwrap();
    println!("services: {:?}", services);

    // Part 1.1: Initiate attestation request (identity initiation).
    let expected_org_name = String::from("My Org");
    let expected_operator_name = String::from("Some Operator");

    let result = initiate_identity_challenge(
        expected_org_name.clone(),
        expected_operator_name.clone(),
        &services,
    )
    .await;
    assert!(result.is_ok());

    // |------------| attestor |------------|
    // Part 1.2: check the serialized data matches that received in 1.1 (this step is done manually)
    // by the upstream in deployment using `trustchain-cli`
    let path = std::env::var(TRUSTCHAIN_DATA).unwrap();
    let attestation_requests_path = PathBuf::from(path).join("attestation_requests");
    // For the test, there should be only one attestation request (subdirectory).
    let paths = fs::read_dir(attestation_requests_path).unwrap();
    let request_path: PathBuf = paths.map(|path| path.unwrap().path()).collect();

    // TODO: Deserialized received information and check that it is correct.
    let identity_initiation = IdentityCRInitiation::new()
        .elementwise_deserialize(&request_path)
        .unwrap()
        .unwrap();
    println!("identity_initiation: {:?}", identity_initiation);
    let org_name = identity_initiation
        .requester_details
        .clone()
        .unwrap()
        .requester_org;
    let operator_name = identity_initiation
        .requester_details
        .clone()
        .unwrap()
        .operator_name;
    // assert_eq!(expected_org_name, org_name);
    // TODO: present identity challenge.

    // |------------| requester |------------|
    // TODO: identity response.
}
