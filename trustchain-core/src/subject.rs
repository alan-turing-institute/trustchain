//! DID subject API.
use crate::utils::get_did_suffix;

/// A DID Subject.
pub trait Subject {
    /// Returns the DID of the subject.
    fn did(&self) -> &str;
    /// Returns the DID suffix of the subject.
    fn did_suffix(&self) -> &str {
        get_did_suffix(self.did())
    }
}
