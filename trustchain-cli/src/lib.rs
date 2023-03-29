pub mod api;
use crate::api::{TrustchainDIDCLI, TrustchainVCCLI};

/// A type for implementing CLI traits on.
pub struct TrustchainCLI;

impl TrustchainDIDCLI for TrustchainCLI {}
impl TrustchainVCCLI for TrustchainCLI {}
