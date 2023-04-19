use trustchain_core::config::core_config;
use trustchain_ion::config::ion_config;

#[test]
#[ignore = "requires a valid `trustchain_config.toml` file at root of TRUSTCHAIN_DATA directory"]
/// Test using both Core and ION config read from `trustchain_config.toml`
fn load_config_from_toml() {
    // Get an item from core_config
    let _ = core_config().root_event_time;
    // Get an item from ion_core
    let _ = &ion_config().mongo_connection_string;
}
