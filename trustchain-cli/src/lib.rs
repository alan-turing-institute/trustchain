use trustchain_ion::{
    utils::{bitcoind_status, ion_ok, ipfs_ok, mongodb_ok, BitcoindStatus},
    TrustchainBitcoinError,
};

pub mod config;

/// Prints the current status of ION and its dependencies.
pub async fn print_status() {
    let bitcoind_status = bitcoind_status().await;
    let mut is_mainnet = false;
    if let BitcoindStatus::Ok(x) = bitcoind_status {
        is_mainnet = x;
    }

    let str = "IPFS......... ".to_string();
    let msg = Some("IPFS daemon not found");
    println!("{}", status_str(str, ipfs_ok().await, msg));

    let str = "MongoDB...... ".to_string();
    let msg = Some("Mongo daemon not found");
    println!("{}", status_str(str, mongodb_ok(is_mainnet).await, msg));

    let str = "Bitcoin...... ".to_string();
    match bitcoind_status {
        BitcoindStatus::Ok(_) => {
            println!("{}", status_str(str, true, None));
        }
        BitcoindStatus::Synching(blocks, headers) => {
            let msg = Some(format!("Synching blocks: {}/{}", blocks, headers));
            println!("{}", status_str(str, false, msg.as_deref()));
        }
        BitcoindStatus::Error(e) => {
            let msg = match e {
                err @ TrustchainBitcoinError::BitcoinCoreRPCError(_) => err.to_string(),
                _ => "Bitcoin RPC returned an error".to_string(),
            };
            println!("{}", status_str(str, false, Some(&msg)));
        }
    };

    let str = "ION.......... ".to_string();
    let msg = Some("ION DID resolution attempt failed");
    println!("{}", status_str(str, ion_ok(is_mainnet).await, msg));

    // TODO: check trustchain-http server status (report only if positive).
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
