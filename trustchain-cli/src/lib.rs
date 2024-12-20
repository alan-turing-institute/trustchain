use config::cli_config;
use trustchain_ion::{
    utils::{bitcoind_status, ion_ok, ipfs_ok, mongodb_ok, BitcoindStatus},
    TrustchainBitcoinError,
};

pub mod config;

/// Prints the current status of ION and its dependencies.
pub async fn print_status() {
    let str = "IPFS......... ".to_string();
    let msg = Some("IPFS daemon not found");
    println!("{}", status_str(str, ipfs_ok().await, msg));

    // Check bitcoind status to determine network (mainnet or testnet).
    let bitcoind_status = bitcoind_status().await;
    let bitcoin_str = "Bitcoin...... ".to_string();
    match bitcoind_status {
        BitcoindStatus::Ok(network) => {
            let mongo_str = "MongoDB...... ".to_string();
            let msg = Some("Mongo daemon not found");
            println!("{}", status_str(mongo_str, mongodb_ok(&network).await, msg));

            println!("{}", status_str(bitcoin_str, true, None));

            let ion_str = "ION.......... ".to_string();
            let msg = Some("ION DID resolution attempt failed");
            let is_ok = ion_ok(&network, cli_config().ion_endpoint.port).await;
            println!("{}", status_str(ion_str, is_ok, msg));
        }
        BitcoindStatus::Synching(blocks, headers) => {
            let msg = Some(format!("Synching blocks: {}/{}", blocks, headers));
            println!("{}", status_str(bitcoin_str, false, msg.as_deref()));
        }
        BitcoindStatus::Error(e) => {
            let msg = match e {
                err @ TrustchainBitcoinError::BitcoinCoreRPCError(_) => err.to_string(),
                _ => "Bitcoin RPC returned an error".to_string(),
            };
            println!("{}", status_str(bitcoin_str, false, Some(&msg)));
        }
    };
}

pub fn status_str(mut str: String, is_ok: bool, details: Option<&str>) -> String {
    if is_ok {
        str.push_str("✅");
        return str;
    }
    str.push_str("❌");
    if let Some(detail) = details {
        str.push_str(" [");
        str.push_str(detail);
        str.push_str("]");
    }
    str
}
