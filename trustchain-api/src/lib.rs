pub mod api;
use crate::api::{TrustchainDIDAPI, TrustchainVCAPI, TrustchainVPAPI};

/// A type for implementing CLI traits on.
pub struct TrustchainAPI;

impl TrustchainDIDAPI for TrustchainAPI {}
impl TrustchainVCAPI for TrustchainAPI {}
impl TrustchainVPAPI for TrustchainAPI {}
