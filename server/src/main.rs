use std::net::SocketAddr;
use std::sync::Arc;

use axum::{routing::post, Json, Router};
use serde::Deserialize;
use base64::Engine as _;
use taric_core::{AckSigner, ChainStore, DeviceTrust, InMemoryChainStore, LogEntry, Verifier, VerifyingKey};
use std::fs;

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
                        Ok(ack) => axum::response::Json(ack),
                        Err(err) => {
                            let ack = taric_core::Ack {
                                entry_id: e.entry_hash.clone(),
                                new_entry_hash: e.entry_hash.clone(),
                                status: format!("error:{err}"),
                                timestamp: chrono::Utc::now().timestamp(),
                                server_signer_id: "server-key-1".into(),
                                server_signature: String::new(),
                            };
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
