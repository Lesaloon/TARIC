use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey as DalekVk};

use crate::errors::VerifyError;
use crate::traits::{ChainStore, DeviceTrust};
use crate::types::{LogEntry, VerifyingKey, compute_entry_hash, cbor_for_sign};
use crate::verifier::{Ed25519AckSigner, InMemoryChainStore, Verifier};

/// Simple static trust for tests.
struct StaticTrust { key: VerifyingKey, revoked: bool }
impl DeviceTrust for StaticTrust {
    fn get_key(&self, device_id: &str, key_id: Option<&str>) -> Option<VerifyingKey> {
        let _ = (device_id, key_id);
        Some(self.key.clone())
    }
    fn is_revoked(&self, _device_id: &str, _key_id: Option<&str>) -> bool { self.revoked }
}

fn make_entry(sign_sk: &SigningKey, device_id: &str, key_id: Option<&str>, prev: Option<&str>, nonce: u64, ts: i64, payload: &str) -> LogEntry {
    let mut e = LogEntry {
        version: 1,
        entry_hash: String::new(),
        device_id: device_id.into(),
        timestamp: ts,
        session_id: "00000000-0000-0000-0000-000000000000".into(),
        nonce,
        algo: "ed25519".into(),
        key_id: key_id.map(|s| s.to_string()),
        payload: payload.into(),
        signature: String::new(),
        previous_entry_hash: prev.map(|s| s.to_string()),
    };
    // compute hash first (excludes entry_hash + signature)
    e.entry_hash = compute_entry_hash(&e);
    // sign over canonical form including entry_hash
    let msg = cbor_for_sign(&e);
    let sig = sign_sk.sign(&msg);
    e.signature = B64.encode(sig.to_bytes());
    e
}

fn keys() -> (SigningKey, DalekVk) {
    let sk_bytes = [42u8; 32];
    let sk = SigningKey::from_bytes(&sk_bytes);
    let vk = DalekVk::from(&sk);
    (sk, vk)
}

fn trust_and_store(vk: &DalekVk) -> (Arc<dyn DeviceTrust>, Arc<dyn ChainStore>) {
    let trust = StaticTrust {
        key: VerifyingKey { algo: "ed25519".to_string(), key: vk.to_bytes().to_vec(), key_id: Some("001-key1-1".into()) },
        revoked: false,
    };
    (Arc::new(trust), Arc::new(InMemoryChainStore::new()))
}

#[test]
fn happy_path_two_entries() {
    let (sk, vk) = keys();
    let (trust, store) = trust_and_store(&vk);
    let signer = Ed25519AckSigner::from_secret_key("server-key-1", [9u8; 32]);
    let verifier = Verifier::new(trust, store, Arc::new(signer));

    let e1 = make_entry(&sk, "dev-1", Some("001-key1-1"), None, 1, 1_700_000_000, "{\"t\":22.5}");
    let ack1 = verifier.process_entry(&e1, 1_700_000_050).expect("e1 accepted");
    assert_eq!(ack1.entry_id, e1.entry_hash);
    assert_eq!(ack1.new_entry_hash, e1.entry_hash);
    assert_eq!(ack1.status, "accepted");

    let e2 = make_entry(&sk, "dev-1", Some("001-key1-1"), Some(&e1.entry_hash), 2, 1_700_000_100, "{\"t\":23.0}");
    let ack2 = verifier.process_entry(&e2, 1_700_000_150).expect("e2 accepted");
    assert_eq!(ack2.entry_id, e2.entry_hash);
}

#[test]
fn rejects_bad_signature() {
    let (sk, vk) = keys();
    let (trust, store) = trust_and_store(&vk);
    let signer = Ed25519AckSigner::from_secret_key("server-key-1", [9u8; 32]);
    let verifier = Verifier::new(trust, store, Arc::new(signer));

    let mut e1 = make_entry(&sk, "dev-1", Some("001-key1-1"), None, 1, 1_700_000_000, "{\"t\":22.5}");
    // flip a bit in signature
    let mut sig = B64.decode(e1.signature.as_bytes()).unwrap();
    sig[0] ^= 0x01;
    e1.signature = B64.encode(sig);
    let err = verifier.process_entry(&e1, 1_700_000_050).unwrap_err();
    assert_eq!(err, VerifyError::InvalidSignature);
}

#[test]
fn rejects_prev_hash_mismatch_and_nonce() {
    let (sk, vk) = keys();
    let (trust, store) = trust_and_store(&vk);
    let signer = Ed25519AckSigner::from_secret_key("server-key-1", [9u8; 32]);
    let verifier = Verifier::new(trust, store, Arc::new(signer));

    let e1 = make_entry(&sk, "dev-1", Some("001-key1-1"), None, 10, 1_700_000_000, "A");
    verifier.process_entry(&e1, 1_700_000_050).unwrap();

    // wrong previous hash
    let bad_prev = make_entry(&sk, "dev-1", Some("001-key1-1"), Some("bad"), 11, 1_700_000_100, "B");
    let err = verifier.process_entry(&bad_prev, 1_700_000_150).unwrap_err();
    assert_eq!(err, VerifyError::PreviousHashMismatch);

    // non-monotonic nonce
    let bad_nonce = make_entry(&sk, "dev-1", Some("001-key1-1"), Some(&e1.entry_hash), 9, 1_700_000_200, "C");
    let err = verifier.process_entry(&bad_nonce, 1_700_000_250).unwrap_err();
    assert_eq!(err, VerifyError::NonceNotMonotonic);
}

#[test]
fn rejects_revoked() {
    let (sk, vk) = keys();
    let trust = StaticTrust {
        key: VerifyingKey { algo: "ed25519".to_string(), key: vk.to_bytes().to_vec(), key_id: Some("001-key1-1".into()) },
        revoked: true,
    };
    let store = InMemoryChainStore::new();
    let signer = Ed25519AckSigner::from_secret_key("server-key-1", [9u8; 32]);
    let verifier = Verifier::new(Arc::new(trust), Arc::new(store), Arc::new(signer));

    let e1 = make_entry(&sk, "dev-1", Some("001-key1-1"), None, 1, 1_700_000_000, "X");
    let err = verifier.process_entry(&e1, 1_700_000_050).unwrap_err();
    assert_eq!(err, VerifyError::Revoked("dev-1".into()));
}

#[test]
fn per_session_nonce_behavior() {
    let (sk, vk) = keys();
    let (trust, store) = trust_and_store(&vk);
    let signer = Ed25519AckSigner::from_secret_key("server-key-1", [9u8; 32]);
    let verifier = Verifier::new(trust, store, Arc::new(signer));

    fn recompute(sign_sk: &SigningKey, e: &mut LogEntry) {
        e.entry_hash = compute_entry_hash(e);
        let msg = cbor_for_sign(e);
        let sig = sign_sk.sign(&msg);
        e.signature = B64.encode(sig.to_bytes());
    }

    // Session A: nonce 1 then 2 accepted
    let mut e1 = make_entry(&sk, "dev-1", Some("001-key1-1"), None, 1, 1_700_000_000, "A");
    e1.session_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa".into();
    recompute(&sk, &mut e1);
    verifier.process_entry(&e1, 1_700_000_010).unwrap();

    let mut e2 = make_entry(&sk, "dev-1", Some("001-key1-1"), Some(&e1.entry_hash), 2, 1_700_000_020, "B");
    e2.session_id = e1.session_id.clone();
    recompute(&sk, &mut e2);
    verifier.process_entry(&e2, 1_700_000_030).unwrap();

    // Session B: can start at 1 again; must link previous_entry_hash device-wide
    let mut e3 = make_entry(&sk, "dev-1", Some("001-key1-1"), Some(&e2.entry_hash), 1, 1_700_000_040, "C");
    e3.session_id = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb".into();
    recompute(&sk, &mut e3);
    verifier.process_entry(&e3, 1_700_000_050).unwrap();

    // Exact +1: nonce 3 expected next in session B; using 5 must fail
    let mut e_bad = make_entry(&sk, "dev-1", Some("001-key1-1"), Some(&e3.entry_hash), 5, 1_700_000_060, "D");
    e_bad.session_id = e3.session_id.clone();
    recompute(&sk, &mut e_bad);
    let err = verifier.process_entry(&e_bad, 1_700_000_070).unwrap_err();
    assert_eq!(err, VerifyError::NonceNotMonotonic);
}
