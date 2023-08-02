//! Operation manager for handling saving and publishing of DID operations.
use did_ion::sidetree::Operation;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum OperationManagerError {
    /// Failed to write operation to file.
    #[error("Failed to write operation to file.")]
    FailedToWrite,
}

pub enum OperationType {
    Create,
    Update,
    Deactivate,
    Recovery,
    Attest,
}

/// Operations can be any of: `Unsent`, `Sent` or `Published`
pub enum OperationStatus {
    Unsent,
    Sent,
    Published,
}

/// A type to use as a key for looking up operations from disk.
pub type OperationID = String;

/// The interface for the operations manager.
trait OperationManager {
    /// Reads operation from operation store.
    fn read(&self, id: OperationID) -> Result<Operation, OperationManagerError>;
    /// Saves operation to operation store.
    fn write(
        &self,
        op: Operation,
        operation_type: OperationType,
    ) -> Result<(), OperationManagerError>;

    /// Restores operation from backup. Moves operation from `Sent` status to `Unsent`.
    /// TODO: Maybe not needed as can also have
    fn restore(&self, _operation_type: OperationType) -> Result<(), OperationManagerError> {
        todo!()
    }

    /// Sends all operations in operation path to ION server.
    fn send(&self) -> Result<(), OperationManagerError> {
        // Glob all files at depth in operation path

        // Post reqwest

        todo!()
    }

    /// Sends all operations in operation path to ION server.
    fn resend(&self) -> Result<(), OperationManagerError> {
        // Glob all files at depth in operation path

        // Post reqwest
        todo!()
    }

    /// Sends operation to ION server.
    fn send_id(&self, _id: OperationID) -> Result<(), OperationManagerError> {
        // Check operation is not already published
        // If it is, move to published
        // Else do reqwest send
        todo!()
    }

    /// Checks whether an operation is resolvable (successfully published)
    fn is_published(&self, id: OperationID) -> bool;

    /// Synchronises the status of the operations path to match whether operations have now been
    /// published, i.e. if OperationStatus is `Sent` and now published, update to `Published`.
    fn synchronise(&self) -> Result<(), OperationManagerError> {
        todo!()
        // For each sent operation, move from sent to published if is_published() is true
        // For each published operation, move from published to Unsent if is_published() now false
    }
}

#[cfg(test)]
mod tests {
    // TODO: Next step is to add some tests to drive development of exact functionality required.
}
