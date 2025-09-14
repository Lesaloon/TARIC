//! TARIC core library: verification, chaining, and ACK signing.
//!
//! Implements the wire format from `docs/api/wire-format.md`:
//! - CBOR-based canonicalization for hashing and signing
//! - SHA-256 entry hashing (hex-encoded)
//! - Ed25519 signature verification for device entries
//! - Server ACK generation and signing
//! - Pluggable device trust and chain state
//!
//! See `docs/context.md` for the high-level overview.

pub mod errors;
pub mod traits;
pub mod types;
pub mod verifier;

pub use errors::VerifyError;
pub use traits::{AckSigner, ChainStore, DeviceTrust};
pub use types::{Ack, LogEntry, VerifyingKey, cbor_for_ack_sign};
pub use verifier::{Ed25519AckSigner, InMemoryChainStore, Verifier};

/// Library version string.
pub fn version() -> &'static str { "taric-core 0.1.0" }

#[cfg(test)]
mod tests;
