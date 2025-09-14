# taric-core

Rust library implementing TARIC’s core verification, chaining, and ACK signing.

## Capabilities

- CBOR canonicalization for hashing and signing (per `docs/api/wire-format.md`)
- SHA-256 `entry_hash` computation (hex)
- Ed25519 signature verification of device entries
- Chain rules: previous hash continuity and strictly increasing nonces per device
- Server ACK construction and signing
- Pluggable `DeviceTrust` (key lookup + revocation)
- Pluggable `ChainStore` (state persistence)

## API Surface

- `struct LogEntry` and `struct Ack`: wire-format structures (serde-serializable)
- `struct Verifier::new(trust, store, ack_signer)`
- `Verifier::process_entry(&LogEntry, now_ts) -> Result<Ack, VerifyError>`
- `Verifier::process_entry_json(&str, now_ts) -> Result<Ack, VerifyError>`
- `trait DeviceTrust { get_key(...), is_revoked(...) }`
- `trait ChainStore { last_hash(...), last_nonce(...), update(...) }`
- `trait AckSigner { signer_id(), sign(msg) }`
- `struct InMemoryChainStore`: simple in-memory store for demos/tests
- `struct Ed25519AckSigner`: basic ACK signer for demos/tests

See inline rustdoc in `src/lib.rs` for details on each method and step of the verification flow.

## Examples

Create a verifier and validate an entry:
```rust
use std::sync::Arc;
use taric_core::{Verifier, InMemoryChainStore, DeviceTrust, VerifyingKey, AckSigner};

struct StaticTrust(VerifyingKey);
impl DeviceTrust for StaticTrust {
    fn get_key(&self, _d: &str, _k: Option<&str>) -> Option<VerifyingKey> { Some(self.0.clone()) }
}
struct NopSigner; impl AckSigner for NopSigner { fn signer_id(&self)->&'static str{"server"} fn sign(&self,m:&[u8])->Vec<u8>{m.to_vec()} }

let trust = Arc::new(StaticTrust(VerifyingKey{ algo: "ed25519".into(), key: vec![0;32], key_id: Some("001".into()) }));
let store = Arc::new(InMemoryChainStore::new());
let signer = Arc::new(NopSigner);
let verifier = Verifier::new(trust, store, signer);
// verifier.process_entry(&entry, now_ts)?;
```

## Tests

Run only core tests:
```bash
bash -lc "cd /mnt/c/Users/guill/code/TARIC && cargo test -p taric-core"
```
