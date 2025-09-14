use serde::{Deserialize, Serialize};
use serde_cbor::to_vec;
use sha2::{Digest, Sha256};

/// Public verifying key material for a device.
#[derive(Clone, Debug)]
pub struct VerifyingKey {
    pub algo: String,
    pub key: Vec<u8>,
    pub key_id: Option<String>,
}

/// Log entry as defined in the wire format.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LogEntry {
    pub version: f32,
    pub entry_hash: String,
    pub device_id: String,
    pub timestamp: i64,
    pub session_id: String,
    pub nonce: u64,
    pub algo: String,
    pub key_id: Option<String>,
    pub payload: String,
    pub signature: String,
    pub previous_entry_hash: Option<String>,
}

/// ACK as defined in the wire format.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Ack {
    pub entry_id: String,
    pub new_entry_hash: String,
    pub status: String,
    pub timestamp: i64,
    pub server_signer_id: String,
    pub server_signature: String,
}

/// Canonicalize a log entry for hashing per docs (exclude entry_hash and signature).
pub fn cbor_for_hash(e: &LogEntry) -> Vec<u8> {
    to_vec(&(
        e.version,
        &e.device_id,
        e.timestamp,
        &e.session_id,
        e.nonce,
        &e.algo,
        &e.key_id,
        &e.payload,
        &e.previous_entry_hash,
    ))
    .expect("CBOR serialization should not fail")
}

/// Canonicalize a log entry for signature per docs (includes entry_hash, excludes signature).
pub fn cbor_for_sign(e: &LogEntry) -> Vec<u8> {
    to_vec(&(
        e.version,
        &e.entry_hash,
        &e.device_id,
        e.timestamp,
        &e.session_id,
        e.nonce,
        &e.algo,
        &e.key_id,
        &e.payload,
        &e.previous_entry_hash,
    ))
    .expect("CBOR serialization should not fail")
}

/// Canonicalize ACK for signing per docs (exclude server_signature).
pub fn cbor_for_ack_sign(a: &Ack) -> Vec<u8> {
    to_vec(&(&a.entry_id, &a.new_entry_hash, &a.status, a.timestamp, &a.server_signer_id))
        .expect("CBOR serialization should not fail")
}

/// Compute hex-encoded SHA-256 of the CBOR-hashed tuple.
pub fn compute_entry_hash(e: &LogEntry) -> String {
    let mut hasher = Sha256::new();
    hasher.update(cbor_for_hash(e));
    let out = hasher.finalize();
    hex::encode(out)
}
