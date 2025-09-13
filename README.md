# TARIC

**TARIC** (Tamper-Resistant IoT Chain) is a platform-agnostic logging framework for **IoT devices** and servers.
It ensures **tamper-evidence**, **cryptographic verification**, and **auditability** of logs across constrained devices and backend systems.

---

## 🚀 Features

- 🔒 **Signed log entries** from IoT devices
- 🔗 **Tamper-proof hash chain** maintained on the server
- 📨 **Signed acknowledgments (ACKs)** so devices can verify server inclusion
- 🌍 **Transport-agnostic** (MQTT, HTTP, TCP … your choice)
- 🪶 Lightweight **C client library** for ESP32 and other MCUs
- ⚡ Secure, memory-safe **Rust core** for the server
- 🧪 CLI verifier for forensic log audits (upcoming)

---

## 🧭 Architecture Overview

### On the IoT Device
- **Your program** generates log events (e.g., sensor readings)
- **TARIC Client (C library)** signs each log entry with the device’s private key
- The signed entry is sent to the server
- Optionally: device verifies a **signed ACK** from the server to confirm the log was chained

### On the Server
- **Your receiver** ingests entries from devices (any protocol)
- **Your program** passes them into the TARIC Core
- **TARIC Core (Rust library)**:
  - Verifies device signature
  - Adds the entry to the tamper-proof chain
  - Writes to append-only log files
  - Issues a **signed ACK** back to the device
- **Log files** can later be audited with the TARIC verifier tool

see /docs/overview.png for a diagram

---

## 📄 Log Entry Format (JSON example)

```json
{
  "device_id": "device123",
  "timestamp": "2025-09-13T10:12:30Z",
  "message": "Temperature: 28.3C",
  "nonce": "a1f9c2...",
  "signature": "base64-encoded-sig"
}
````

---

## 📄 ACK Format (JSON example)

```json
{
  "entry_id": 42,
  "previous_hash": "7b4c2d...",
  "new_entry_hash": "c5f9a8...",
  "status": "accepted",
  "timestamp": "2025-09-13T10:12:31Z",
  "server_signature": "base64-encoded-sig"
}
```

> ⚠️ ACKs are **not part of the tamper-proof chain**, but they let the device confirm that the server accepted and chained the log entry.

---

## 🛠️ Build & Run

### ESP32 Client

```bash
cd clients/esp32
idf.py build flash monitor
```

### TARIC Server

```bash
cd server
cargo run --release
```

### CLI Verifier

```bash
cd tools/verifier
cargo run --release -- verify ../server/logs/session1.log
```

---

## 📋 License

TARIC is licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)**.
You may use it commercially, but **any modifications must also be open-sourced under the same license**.

---

## 🤝 Contributing

Contributions are welcome!
Feel free to open issues, submit pull requests, or share your integration stories.

---
