# TARIC Server (demo)

A minimal HTTP server that exposes a single endpoint to verify and chain TARIC entries using the `taric-core` library.

- Binary: `taric-server`
- Endpoint: `POST /entries`
- Request body: `LogEntry` JSON (wire format fields)
- Response body: `Ack` JSON

## What it does

- Loads the device public key from a shared fixture (`/fixtures/devices/device.json`) on every request.
- Verifies the entry's `entry_hash` and signature using the supplied algorithm (Ed25519 supported now).
- Enforces chaining rules: `previous_entry_hash` continuity per device and `nonce` exactly +1 per device per session.
- Updates in-memory chain state and returns a signed ACK with status `accepted`.
- On failure, returns an `Ack`-shaped error with `status: "error:<reason>"`.
 - Persists every received entry (accepted or error) to a JSONL file and exposes a list endpoint.

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

You can also generate fixtures with `scripts/setup-devices.sh`, which writes both `devices.json` (array) and `device.json` (single). The server currently reads `device.json`; `devices.json` support can be added by extending the trust implementation.

## Endpoints

- `POST /entries`: Submit a `LogEntry` JSON, receive an `Ack` JSON.
- `GET /entries`: Returns a JSON array of stored records. Each record is:
  ```json
  { "status": "accepted" | "error:<reason>", "entry": { /* LogEntry */ }, "recorded_at": <unix_ts> }
  ```

Entries are appended to `tests-e2e/fixtures/entries.jsonl` (one JSON document per line).

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

## Server Signing Key

ACKs are signed with an Ed25519 server key loaded from JSON:

Path: `tests-e2e/fixtures/server/server_key.json` (inside containers: `/fixtures/server/server_key.json`)

Format:
```json
{ "signer_id": "server-key-1", "algo": "ed25519", "secret_key_base64": "<32-byte seed in base64>" }
```

Generate a key with the helper script:
```bash
bash scripts/setup-server-key.sh
```

Override the path with `TARIC_SERVER_KEY_PATH` if needed. If no key is found, the server uses an ephemeral dev key and logs a warning.
