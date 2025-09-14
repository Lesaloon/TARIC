use std::net::SocketAddr;
use std::sync::Arc;

use axum::{routing::{get, post}, Json, Router};
use serde::Deserialize;
use base64::Engine as _;
use taric_core::{AckSigner, ChainStore, DeviceTrust, InMemoryChainStore, LogEntry, Verifier, VerifyingKey};
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use serde_json::json;

#[derive(Clone)]
struct StaticTrust { key: VerifyingKey }
impl DeviceTrust for StaticTrust {
    fn get_key(&self, _device_id: &str, _key_id: Option<&str>) -> Option<VerifyingKey> { Some(self.key.clone()) }
}

struct NopSigner;
impl AckSigner for NopSigner {
    fn signer_id(&self) -> &'static str { "server-key-1" }
    fn sign(&self, msg: &[u8]) -> Vec<u8> { use ed25519_dalek::{SigningKey, Signer}; let sk = SigningKey::from_bytes(&[7u8;32]); sk.sign(msg).to_bytes().to_vec() }
}


#[derive(Deserialize)]
#[derive(Debug, Clone)]
struct DeviceFixture { device_id: String, algo: String, key_id: String, pubkey_base64: String }

#[tokio::main]
async fn main() {
    let store: Arc<dyn ChainStore> = Arc::new(InMemoryChainStore::new());
    let ack_signer: Arc<dyn AckSigner> = Arc::new(NopSigner);
    let store_cloned = store.clone();
    let ack_signer_cloned = ack_signer.clone();

    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/entries", get({
            move || async move {
                let path = "/fixtures/entries.jsonl";
                let body = if let Ok(s) = fs::read_to_string(path) {
                    // Convert JSONL to JSON array
                    let mut arr = Vec::new();
                    for line in s.lines() {
                        if line.trim().is_empty() { continue; }
                        if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) { arr.push(v); }
                    }
                    serde_json::to_string(&arr).unwrap_or_else(|_| "[]".to_string())
                } else {
                    "[]".to_string()
                };
                axum::response::Response::builder()
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(axum::body::Body::from(body))
                    .unwrap()
            }
        }))
        .route("/entries", post({
            move |Json(e): Json<LogEntry>| {
                let store = store_cloned.clone();
                let ack_signer = ack_signer_cloned.clone();
                async move {
                    // Reload device fixture each request so the runner can provide key dynamically
                    let fixture_path = "/fixtures/devices/device.json";
                    let vk = if let Ok(s) = fs::read_to_string(fixture_path) {
                        let f: DeviceFixture = serde_json::from_str(&s).expect("invalid device fixture JSON");
                        // ensure request device matches fixture device
                        if f.device_id != e.device_id {
                            return axum::response::Json(taric_core::Ack {
                                entry_id: e.entry_hash.clone(), new_entry_hash: e.entry_hash.clone(),
                                status: format!("error:device_unknown:{}", e.device_id),
                                timestamp: chrono::Utc::now().timestamp(),
                                server_signer_id: "server-key-1".into(), server_signature: String::new()
                            });
                        }
                        let key = base64::engine::general_purpose::STANDARD.decode(f.pubkey_base64.as_bytes()).expect("invalid pubkey b64");
                        VerifyingKey { algo: f.algo, key, key_id: Some(f.key_id) }
                    } else {
                        VerifyingKey { algo: "ed25519".to_string(), key: vec![1u8; 32], key_id: Some("001-key1-1".into()) }
                    };
                    let trust = Arc::new(StaticTrust { key: vk });
                    let verifier = Verifier::new(trust, store, ack_signer);
                    match verifier.process_entry(&e, chrono::Utc::now().timestamp()) {
                        Ok(ack) => {
                            append_entry_jsonl(&e, &ack.status);
                            axum::response::Json(ack)
                        },
                        Err(err) => {
                            let ack = taric_core::Ack {
                                entry_id: e.entry_hash.clone(),
                                new_entry_hash: e.entry_hash.clone(),
                                status: format!("error:{err}"),
                                timestamp: chrono::Utc::now().timestamp(),
                                server_signer_id: "server-key-1".into(),
                                server_signature: String::new(),
                            };
                            append_entry_jsonl(&e, &ack.status);
                            axum::response::Json(ack)
                        }
                    }
                }
            }
        }));

    let addr: SocketAddr = "0.0.0.0:8080".parse().unwrap();
    println!("taric-server listening on {addr}");
    axum::serve(tokio::net::TcpListener::bind(addr).await.unwrap(), app).await.unwrap();
}

fn append_entry_jsonl(e: &LogEntry, status: &str) {
    let path = "/fixtures/entries.jsonl";
    let rec = json!({
        "status": status,
        "entry": e,
        "recorded_at": chrono::Utc::now().timestamp(),
    });
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(f, "{}", rec.to_string());
    }
}
