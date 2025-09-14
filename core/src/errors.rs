use thiserror::Error;

/// Errors that can arise while processing a log entry.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum VerifyError {
    #[error("malformed entry: {0}")]
    Malformed(String),
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgo(String),
    #[error("device unknown: {0}")]
    DeviceUnknown(String),
    #[error("revoked key for device {0}")]
    Revoked(String),
    #[error("hash mismatch: provided entry_hash does not match computed")]
    HashMismatch,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("previous hash mismatch")]
    PreviousHashMismatch,
    #[error("nonce not monotonic")]
    NonceNotMonotonic,
}
