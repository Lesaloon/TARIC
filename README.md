# TARIC

TARIC (Tamper-Resistant IoT Chain) is a lightweight protocol and toolkit for tamper-evident device logs.
Devices sign entries, servers verify and chain them, and servers return signed ACKs so devices can confirm inclusion.

— See `docs/context.md` for a quick intro and `docs/api/wire-format.md` for the exact wire format.

## Features

- Signed device entries (Ed25519 initially)
- Tamper-evident chaining via `previous_entry_hash` and SHA-256
- Signed server ACKs for inclusion confirmation
- Pluggable trust (bring-your-own key source / revocation)
- Minimal Rust core, C client (ESP32 WIP), Python example client
- Per-session nonces: strictly +1 per device per session (prevents replay within a session while allowing fresh sessions)

## Architecture

- Device: builds an entry, computes `entry_hash` over CBOR-canonicalized fields, signs the canonical message, and sends JSON.
- Server: verifies hash + signature using device’s public key from a trust source, enforces chain rules (device-wide previous hash continuity; per-session nonce exactly +1), persists state, returns a signed ACK.

High-level diagram: `docs/diagrams/overview.png`.

## Wire Format (summary)

Log Entry fields (see full spec for ordering):
- version (integer), entry_hash, device_id, timestamp, session_id, nonce, algo, key_id, payload, signature, previous_entry_hash

ACK fields:
- entry_id, new_entry_hash, status, timestamp, server_signer_id, server_signature

Canonicalization uses CBOR with strict field ordering; the `signature` is computed over the canonicalized tuple that includes the `entry_hash`. The `entry_hash` is computed over the canonicalized tuple that excludes `entry_hash` and `signature`.

## Quickstart

Rust workspace:
```bash
bash -lc "cd /mnt/c/Users/guill/code/TARIC && cargo build"
```

Run only the core unit tests:
```bash
bash -lc "cd /mnt/c/Users/guill/code/TARIC && cargo test -p taric-core"
```

End-to-end (Docker):
```bash
bash -lc "cd /mnt/c/Users/guill/code/TARIC/tests-e2e && docker compose -f compose.yml up --build --abort-on-container-exit"
```

This starts a simple HTTP server (`taric-server`) and a Python runner that generates a device key, sends two valid chained entries (accepted), then a replay with duplicate nonce in the same session (rejected). The server also appends every received entry (accepted or error) to `tests-e2e/fixtures/entries.jsonl`, and exposes `GET /entries` to list them.

Write-only mode (send N chained entries in one session, no assertions):
```bash
bash -lc "cd /mnt/c/Users/guill/code/TARIC/tests-e2e && ENTRY_COUNT=5 docker compose -f compose.yml up --build --abort-on-container-exit"
```

Inspect stored entries (from host):
```bash
cat tests-e2e/fixtures/entries.jsonl
```
Or from API (if server is bound locally):
```bash
curl http://127.0.0.1:8080/entries
```

## Repos & Components

- `core/`: Rust library implementing the verification logic and ACK signing.
- `server/`: minimal HTTP demo server using the core. See `server/README.md`.
	- Endpoints: `POST /entries` (verify + chain) and `GET /entries` (list stored entries)
	- Logging: appends records to `tests-e2e/fixtures/entries.jsonl`
- `clients/`: device-side clients (C/ESP32 WIP).
- `examples/client-python/`: toy Python client.
- `tests-e2e/`: dockerized end-to-end tests.

## License

AGPL-3.0-only. See `LICENSE`.

## Contributing

Issues and PRs welcome.
