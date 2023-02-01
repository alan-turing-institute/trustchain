use clap::StructOpt;
use std::net::IpAddr;

/// Config for server.
#[derive(StructOpt, Debug, Clone)]
pub struct ServerConfig {
    /// Hostname for server
    #[clap(env, short = 's', long)]
    pub host: IpAddr,
    /// Port for server
    #[clap(env, short = 'p', long)]
    pub port: u16,
}
