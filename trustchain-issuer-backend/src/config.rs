use clap::StructOpt;

/// Config for server.
#[derive(StructOpt, Debug, Clone)]
pub struct ServerConfig {
    /// Hostname for server
    #[clap(env, short = 's', long)]
    pub host: String,
    /// Port for server
    #[clap(env, short = 'p', long)]
    pub port: String,
}
