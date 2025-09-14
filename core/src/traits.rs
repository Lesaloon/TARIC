/// Abstraction over device trust. Implementers decide how to map (device_id, key_id)
/// to a verifying key, and whether a key is revoked.
use crate::types::VerifyingKey;

pub trait DeviceTrust: Send + Sync {
    /// Return a verifying key for `device_id` and an optional `key_id`.
    fn get_key(&self, device_id: &str, key_id: Option<&str>) -> Option<VerifyingKey>;
    /// Indicate whether a device/key is revoked (if true, verification must fail).
    fn is_revoked(&self, _device_id: &str, _key_id: Option<&str>) -> bool { false }
}

/// Server-side ACK signer. Used to sign acknowledgements sent back to devices.
pub trait AckSigner: Send + Sync {
    /// Identifier for the server signing key (e.g. "server-key-1").
    fn signer_id(&self) -> &'static str;
    /// Produce a signature over the canonicalized ACK fields.
    fn sign(&self, msg: &[u8]) -> Vec<u8>;
}

/// Trait to persist minimal chain state per device.
pub trait ChainStore: Send + Sync {
    /// Get the last known hash, if any, for a device.
    fn last_hash(&self, device_id: &str) -> Option<String>;
    /// Get the last known nonce, if any, for a device.
    fn last_nonce(&self, device_id: &str) -> Option<u64>;
    /// Update the (hash, nonce) for a device after accepting an entry.
    fn update(&self, device_id: &str, last_hash: String, last_nonce: u64);
}
