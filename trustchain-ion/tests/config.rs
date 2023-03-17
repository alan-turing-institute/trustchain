use trustchain_config::config;

// test using imported constants from trustchain_config.toml
#[test]
fn load_config() {
    assert_eq!(
        config().ion.mongo_connection_string,
        "mongodb://localhost:27017/"
    );
    assert_eq!(config().core.root_event_time, 1666265405);
}
