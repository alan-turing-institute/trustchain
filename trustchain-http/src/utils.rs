use crate::config::HTTPConfig;
use std::sync::Once;
use tokio::runtime::Runtime;
use trustchain_core::utils::init;

static INIT_HTTP: Once = Once::new();
pub fn init_http() {
    INIT_HTTP.call_once(|| {
        init();
        let http_config = HTTPConfig {
            host: "127.0.0.1".parse().unwrap(),
            port: 8081,
            server_did: Some(
                "did:ion:test:EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A".to_owned(),
            ),
            root_event_time: Some(1666265405),
            ..Default::default()
        };

        // Run test server in own thread
        std::thread::spawn(|| {
            let rt = Runtime::new().unwrap();
            rt.block_on(async {
                crate::server::http_server(http_config).await.unwrap();
            });
        });
    });
}
