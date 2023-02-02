use std::{net::IpAddr, str::FromStr};
const DEFAULT_HOST: &str = "127.0.0.1";
const DEFAULT_PORT: u16 = 8081;

/// Server config.
#[derive(clap::Parser, Debug, Clone)]
pub struct ServerConfig {
    /// Hostname for server
    #[clap(short = 's', long)]
    #[arg(default_value_t = IpAddr::from_str(DEFAULT_HOST).unwrap())]
    pub host: IpAddr,
    /// Hostname reference. For example, Android emulator 10.0.2.2 refers to 127.0.0.1 of machine running emulator.
    #[clap(short = 'r', long)]
    #[arg(default_value_t = IpAddr::from_str(DEFAULT_HOST).unwrap())]
    pub host_reference: IpAddr,
    /// Port for server
    #[clap(short = 'p', long)]
    #[arg(default_value_t = DEFAULT_PORT)]
    pub port: u16,
}

impl std::fmt::Display for ServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Host: {} | Host reference: {} | Port: {}",
            self.host, self.host_reference, self.port
        )?;
        Ok(())
    }
}
