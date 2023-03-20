use trustchain_core::config::core_config;
use trustchain_ion::config::ion_config;

// test using imported constants from trustchain_config.toml
#[test]
#[ignore = "Requires a valid trustchain_config.toml file at root of directory"]
fn load_config_from_toml() {
    // test loading trustchain_config.toml (looks at root of directory)
    &ion_config().mongo_connection_string;
    core_config().root_event_time;
}
