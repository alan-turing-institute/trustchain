use trustchain_core::config::core_config;
use trustchain_ion::config::ion_config;

#[test]
#[ignore = "requires a valid `trustchain_config.toml` file at root of TRUSTCHAIN_DATA directory"]
/// Test using both Core and ION config read from `trustchain_config.toml`
fn load_config_from_toml() {
    core_config().root_event_time;
    let _ = &ion_config().mongo_connection_string;
}
