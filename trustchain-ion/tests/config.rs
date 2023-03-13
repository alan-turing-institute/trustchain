use trustchain_config::get_config;

// test using imported constants from trustchain_config.toml
#[test]
fn load_config() {
    let trustchain_config = get_config();
    assert_eq!(
        trustchain_config.ion.mongo_connection_string,
        "mongodb://localhost:27017/"
    );
}
