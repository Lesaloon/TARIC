# TARIC Server (demo)

A minimal HTTP server that exposes a single endpoint to verify and chain TARIC entries using the `taric-core` library.

- Binary: `taric-server`
- Endpoint: `POST /entries`
- Request body: `LogEntry` JSON (wire format fields)
- Response body: `Ack` JSON

## What it does

- Loads the device public key from a shared fixture (`/fixtures/devices/device.json`) on every request.
- Verifies the entry's `entry_hash` and signature using the supplied algorithm (Ed25519 supported now).
- Enforces chaining rules: `previous_entry_hash` continuity and strictly increasing `nonce` per device.
- Updates in-memory chain state and returns a signed ACK with status `accepted`.
- On failure, returns an `Ack`-shaped error with `status: "error:<reason>"`.

## Fixture format

Path: `/fixtures/devices/device.json`
```json
{
  "device_id": "<uuid>",
  "algo": "ed25519",
  "key_id": "001-key1-1",
  "pubkey_base64": "<base64 of 32-byte ed25519 public key>"
}
```

This demo server reloads the fixture per request to simplify testing. In production, provide a `DeviceTrust` backed by your PKI/DB.

## Run (dev)

From repo root:
```bash
bash -lc "cd /mnt/c/Users/guill/code/TARIC && cargo run -p taric-server"
```
Then POST a `LogEntry` JSON to `http://127.0.0.1:8080/entries`.

For a full demo, run the dockerized e2e in `tests-e2e/` (see root README Quickstart).

## Extend it

- Replace the per-request fixture trust with a real trust provider implementing `DeviceTrust`.
- Swap `InMemoryChainStore` for a persistent store (DB, append-only log).
- Add authentication, rate limits, metrics, and structured logging.
