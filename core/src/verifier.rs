use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey as DalekVerifyingKey, Signer as _, Verifier as _};

use crate::errors::VerifyError;
use crate::traits::{AckSigner, ChainStore, DeviceTrust};
use crate::types::{Ack, LogEntry, VerifyingKey, cbor_for_ack_sign, cbor_for_sign, compute_entry_hash};

/// Simple in-memory chain store suitable for tests and single-process demos.
#[derive(Default)]
pub struct InMemoryChainStore {
    inner: Mutex<HashMap<String, (String, u64)>>,
}

impl InMemoryChainStore {
    /// Create a new, empty in-memory chain store.
    pub fn new() -> Self { Self { inner: Mutex::new(HashMap::new()) } }
}

impl ChainStore for InMemoryChainStore {
    fn last_hash(&self, device_id: &str) -> Option<String> {
        self.inner.lock().unwrap().get(device_id).map(|(h, _)| h.clone())
    }
    fn last_nonce(&self, device_id: &str) -> Option<u64> {
        self.inner.lock().unwrap().get(device_id).map(|(_, n)| *n)
    }
    fn update(&self, device_id: &str, last_hash: String, last_nonce: u64) {
        self.inner.lock().unwrap().insert(device_id.to_string(), (last_hash, last_nonce));
    }
}

/// Verifier coordinates trust, chain state, and ACK signing.
pub struct Verifier {
    trust: Arc<dyn DeviceTrust>,
    store: Arc<dyn ChainStore>,
    ack_signer: Arc<dyn AckSigner>,
}

impl Verifier {
    /// Create a new `Verifier` with the given trust source, chain store, and ACK signer.
    pub fn new(trust: Arc<dyn DeviceTrust>, store: Arc<dyn ChainStore>, ack_signer: Arc<dyn AckSigner>) -> Self {
        Self { trust, store, ack_signer }
    }

    /// Verify a log entry JSON, update the chain state, and return a signed ACK.
    pub fn process_entry_json(&self, json: &str, now_ts: i64) -> Result<Ack, VerifyError> {
        let entry: LogEntry = serde_json::from_str(json).map_err(|e| VerifyError::Malformed(e.to_string()))?;
        self.process_entry(&entry, now_ts)
    }

    /// Verify a parsed `LogEntry`, enforce chain rules, and return a signed ACK.
    pub fn process_entry(&self, entry: &LogEntry, now_ts: i64) -> Result<Ack, VerifyError> {
        // 1) Hash check
        let computed = compute_entry_hash(entry);
        if computed != entry.entry_hash { return Err(VerifyError::HashMismatch); }

        // 2) Trust lookup
        let vk = self.trust
            .get_key(&entry.device_id, entry.key_id.as_deref())
            .ok_or_else(|| VerifyError::DeviceUnknown(entry.device_id.clone()))?;
        if self.trust.is_revoked(&entry.device_id, entry.key_id.as_deref()) {
            return Err(VerifyError::Revoked(entry.device_id.clone()));
        }
        if vk.algo != entry.algo {
            return Err(VerifyError::UnsupportedAlgo(entry.algo.clone()));
        }

        // 3) Signature verify
        match entry.algo.as_str() {
            "ed25519" => {
                if vk.key.len() != 32 { return Err(VerifyError::Malformed("ed25519 pubkey length".into())); }
                let mut pk_bytes = [0u8; 32];
                pk_bytes.copy_from_slice(&vk.key);
                let pk = DalekVerifyingKey::from_bytes(&pk_bytes).map_err(|_| VerifyError::Malformed("bad ed25519 pubkey".into()))?;
                let sig_bytes = B64.decode(entry.signature.as_bytes()).map_err(|_| VerifyError::Malformed("signature base64".into()))?;
                let sig = Signature::from_slice(&sig_bytes).map_err(|_| VerifyError::Malformed("signature length".into()))?;
                let msg = cbor_for_sign(entry);
                pk.verify(&msg, &sig).map_err(|_| VerifyError::InvalidSignature)?;
            }
            other => return Err(VerifyError::UnsupportedAlgo(other.to_string())),
        }

        // 4) Chain rules
        let last_h = self.store.last_hash(&entry.device_id);
        let last_n = self.store.last_nonce(&entry.device_id);
        match (last_h, &entry.previous_entry_hash) {
            (None, None) => { /* first entry OK */ }
            (Some(h), Some(prev)) if h == *prev => { /* OK */ }
            (Some(_), None) | (None, Some(_)) => return Err(VerifyError::PreviousHashMismatch),
            (Some(h), Some(prev)) if h != *prev => return Err(VerifyError::PreviousHashMismatch),
            _ => {}
        }
        if let Some(n) = last_n { if entry.nonce <= n { return Err(VerifyError::NonceNotMonotonic); } }

        // 5) Accept: update chain state and ACK
        self.store.update(&entry.device_id, entry.entry_hash.clone(), entry.nonce);
        let ack = self.make_ack(entry, now_ts);
        Ok(ack)
    }

    /// Construct and sign an ACK for an accepted entry.
    fn make_ack(&self, entry: &LogEntry, now_ts: i64) -> Ack {
        let server_signer_id = self.ack_signer.signer_id();
        let mut ack = Ack {
            entry_id: entry.entry_hash.clone(),
            new_entry_hash: entry.entry_hash.clone(),
            status: "accepted".into(),
            timestamp: now_ts,
            server_signer_id: server_signer_id.into(),
            server_signature: String::new(),
        };
        let msg = cbor_for_ack_sign(&ack);
        let sig = self.ack_signer.sign(&msg);
        ack.server_signature = B64.encode(sig);
        ack
    }
}

/// Ed25519 implementation of `AckSigner` suitable for tests and demos.
pub struct Ed25519AckSigner {
    id: &'static str,
    sk: SigningKey,
}

impl Ed25519AckSigner {
    /// Create a signer from a fixed 32-byte secret key and static identifier.
    pub fn from_secret_key(id: &'static str, secret_key: [u8; 32]) -> Self {
        Self { id, sk: SigningKey::from_bytes(&secret_key) }
    }
}

impl AckSigner for Ed25519AckSigner {
    fn signer_id(&self) -> &'static str { self.id }
    fn sign(&self, msg: &[u8]) -> Vec<u8> { self.sk.sign(msg).to_bytes().to_vec() }
}
