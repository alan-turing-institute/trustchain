//! Utilities to display DID.
use ssi::did::{Document, Service, ServiceEndpoint};
use ssi::one_or_many::OneOrMany;
use std::fmt;

use crate::TRUSTCHAIN_SERVICE_ID_VALUE;

/// Truncates a string to be of maximum length `max_chars` and adds ellipsis.
fn truncate(s: &str, max_chars: usize) -> String {
    match s.char_indices().nth(max_chars) {
        None => s.to_string(),
        Some((idx, _)) => s[..idx - 3].to_string() + "...",
    }
}

/// Extracts the service endpoint string from a DID `Document` if exactly one service with
/// "id": `TrustchainID` is present.
fn get_service_endpoint_string(doc: &Document) -> Option<String> {
    match doc.select_service(TRUSTCHAIN_SERVICE_ID_VALUE) {
        Some(Service {
            service_endpoint: Some(OneOrMany::One(ServiceEndpoint::URI(service_endpoint))),
            ..
        }) => Some(service_endpoint.to_string()),
        _ => None,
    }
}

/// A struct for displaying a DID in a box.
pub struct PrettyDID {
    did: String,
    level: usize,
    endpoint: Option<String>,
    max_width: usize,
}

impl PrettyDID {
    pub fn new(doc: &Document, level: usize, max_width: usize) -> Self {
        let endpoint = get_service_endpoint_string(doc);
        Self {
            did: doc.id.to_string(),
            level,
            endpoint,
            max_width,
        }
    }
    pub fn get_width(&self) -> usize {
        format!(" DID: {} ", self.did).len().min(self.max_width)
    }
    fn get_text_width(&self) -> usize {
        self.get_width() - 2
    }
    pub fn get_strings(&self) -> [String; 3] {
        let text_width = self.get_text_width();
        let level_string = truncate(&format!("Level: {}", self.level), text_width);
        let did_string = truncate(&format!("DID: {}", self.did), text_width);
        let endpoint_string = match &self.endpoint {
            Some(s) => truncate(&format!("Endpoint: {}", s), text_width),
            _ => truncate(&format!("Endpoint: {}", ""), text_width),
        };
        [level_string, did_string, endpoint_string]
    }
    pub fn to_node_string(&self) -> String {
        let strings = self.get_strings();
        strings.join("\n")
    }
}

impl fmt::Display for PrettyDID {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Style:
        // "+---------------+"
        // "| level: ...    |"
        // "| did: ...      |"  ✅
        // "| endpoint: ... |"
        // "+---------------+"
        let box_width = self.get_width();
        let text_width = box_width - 2;
        let [level_string, did_string, endpoint_string] = self.get_strings();
        writeln!(f, "+{}+", "-".repeat(box_width))?;
        writeln!(f, "| {0:<1$} |   ", level_string, text_width)?;
        writeln!(f, "| {0:<1$} |  ✅", did_string, text_width)?;
        writeln!(f, "| {0:<1$} |   ", endpoint_string, text_width)?;
        writeln!(f, "+{}+", "-".repeat(box_width))?;
        Ok(())
    }
}
