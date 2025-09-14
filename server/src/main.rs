use std::net::SocketAddr;
use std::sync::Arc;

use axum::{routing::{get, post}, Json, Router};
use serde::Deserialize;
use base64::Engine as _;
use taric_core::{AckSigner, ChainStore, DeviceTrust, InMemoryChainStore, LogEntry, Verifier, VerifyingKey, Ed25519AckSigner};
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use serde_json::json;

#[derive(Clone)]
struct StaticTrust { key: VerifyingKey }
impl DeviceTrust for StaticTrust {
    fn get_key(&self, _device_id: &str, _key_id: Option<&str>) -> Option<VerifyingKey> { Some(self.key.clone()) }
}

#[derive(Deserialize)]
struct ServerKeyFixture { signer_id: String, algo: String, secret_key_base64: String }

fn load_server_signer() -> Arc<dyn AckSigner> {
    let path = std::env::var("TARIC_SERVER_KEY_PATH").unwrap_or_else(|_| "/fixtures/server/server_key.json".to_string());
    match fs::read_to_string(&path) {
        Ok(s) => {
            match serde_json::from_str::<ServerKeyFixture>(&s) {
                Ok(f) => {
                    if f.algo != "ed25519" { eprintln!("Unsupported server key algo: {}", f.algo); }
                    let sk_bytes = match base64::engine::general_purpose::STANDARD.decode(f.secret_key_base64.as_bytes()) {
                        Ok(b) => b,
                        Err(e) => { eprintln!("Failed to decode server secret key b64: {e}"); vec![7u8;32] }
                    };
                    let mut arr = [0u8; 32];
                    if sk_bytes.len() == 32 { arr.copy_from_slice(&sk_bytes); } else { eprintln!("Server secret key must be 32 bytes (seed)"); }
                    Arc::new(Ed25519AckSigner::from_secret_key(Box::leak(f.signer_id.into_boxed_str()), arr)) as Arc<dyn AckSigner>
                }
                Err(e) => { eprintln!("Invalid server key JSON: {e}"); Arc::new(Ed25519AckSigner::from_secret_key("server-dev", [7u8;32])) }
            }
        }
        Err(_) => {
            eprintln!("Server key not found at {path}; using ephemeral dev key. Set TARIC_SERVER_KEY_PATH or create fixtures/server/server_key.json");
            Arc::new(Ed25519AckSigner::from_secret_key("server-dev", [7u8;32]))
        }
    }
}


#[derive(Deserialize)]
#[derive(Debug, Clone)]
struct DeviceFixture { device_id: String, algo: String, key_id: String, pubkey_base64: String }

#[tokio::main]
async fn main() {
    let store: Arc<dyn ChainStore> = Arc::new(InMemoryChainStore::new());
    let ack_signer: Arc<dyn AckSigner> = load_server_signer();
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
                    let ack_signer_for_verifier = ack_signer.clone();
                    let verifier = Verifier::new(trust, store, ack_signer_for_verifier);
                    match verifier.process_entry(&e, chrono::Utc::now().timestamp()) {
                        Ok(ack) => {
                            append_entry_jsonl(&e, &ack.status);
                            axum::response::Json(ack)
                        },
                        Err(err) => {
                            let mut ack = taric_core::Ack {
                                entry_id: e.entry_hash.clone(),
                                new_entry_hash: e.entry_hash.clone(),
                                status: format!("error:{err}"),
                                timestamp: chrono::Utc::now().timestamp(),
                                server_signer_id: ack_signer.signer_id().to_string(),
                                server_signature: String::new(),
                            };
                            let msg = taric_core::cbor_for_ack_sign(&ack);
                            let sig = ack_signer.sign(&msg);
                            ack.server_signature = base64::engine::general_purpose::STANDARD.encode(sig);
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
