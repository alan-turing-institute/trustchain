pub mod api;
use crate::api::{TrustchainDIDAPI, TrustchainVCAPI};

/// A type for implementing CLI traits on.
pub struct TrustchainAPI;

impl TrustchainDIDAPI for TrustchainAPI {}
impl TrustchainVCAPI for TrustchainAPI {}
