import json, requests, time
ENTRY = {
  "device_id": "dev-001",
  "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
  "nonce": "demo-nonce",
  "algo": "none",
  "key_id": "none",
  "payload": "Hello from Python client",
  "signature": ""
}
print("POSTing demo entry:", json.dumps(ENTRY))
# TODO: set your server URL
# requests.post("http://127.0.0.1:8080/log", json=ENTRY, timeout=5)
