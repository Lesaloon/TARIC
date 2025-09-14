# TARIC Wire Format

## Log Entry

  version: 1,
    entry_hash: string (SHA-256 hex) this entry's hash (excluding this field and the signature fields)
    device_id: string (UUID v4)
    timestamp: integer (Unix epoch seconds)
    session_id: string (UUID v4) to group entries from the same device session, e.g. after a reboot
  nonce: integer (per device per session, increments by exactly +1) to prevent replay attacks within a session
    algo: string (e.g. "ed25519")
    key_id: string (key identifier, e.g. "001-key1") to allow key rotation ( ddd-keyN where N is the Nth key for device ddd)
    payload: string (opaque, e.g. JSON blob or binary data, base64-encoded if binary...)
    signature: string (base64-encoded signature of the above fields, in order, using the specified algo and key)
    previous_entry_hash: string (hash of the previous log entry in the chain, or null if first)

### example

```json
{
  "version": 1, // version of the log entry format (integer)
  "entry_hash": "5f4dcc3b5aa765d61d8327deb882cf99", // SHA-256 hex of this entry (excluding this field)
  "device_id": "550e8400-e29b-41d4-a716-446655440000", // UUID v4
  "timestamp": 1700000000, // Unix epoch seconds
  "session_id": "550e8400-e29b-41d4-a716-446655440001", // UUID v4
  "nonce": 1, // increments by exactly +1 per device per session
  "algo": "ed25519", // signing algorithm (e.g. "ed25519", "rsa-2048")
  "key_id": "001-key1-1", // key identifier for key rotation (ddd-keyN)
  "payload": "{\"temperature\": 22.5, \"humidity\": 45}", // opaque payload (e.g. JSON blob or binary data, base64-encoded if binary)
  "signature": "MEUCIQDf...base64...IDAQAB", // base64-encoded signature of the above fields using the specified algo and key
  "previous_entry_hash": "3a7bd3e2360a3d..." // hash of the previous log entry in the chain, or null if first
}
```

### canonicalization for hashing

We use CBOR for canonicalization before hashing, to ensure a stable binary representation of the log entry fields. The fields are serialized in the following order (excluding `entry_hash` and `signature`):
1. version
2. device_id
3. timestamp
4. session_id
5. nonce
6. algo
7. key_id
8. payload
9. previous_entry_hash

### canonicalization for signing

We use CBOR for canonicalization before signing, to ensure a stable binary representation of the log entry fields. The fields are serialized in the following order (excluding `signature`):
1. version
2. entry_hash
3. device_id
4. timestamp
5. session_id
6. nonce
7. algo
8. key_id
9. payload
10. previous_entry_hash

The `signature` field is excluded from canonicalization as it is derived from the other fields. The device-wide chain continuity is enforced via `previous_entry_hash` linking to the last accepted entry for the device.

## ACK

    entry_id: string (hash of the log entry being acknowledged, e.g. SHA-256 hex)
    new_entry_hash: string (hash of the new log entry being added, e.g. SHA-256 hex)
    status: string (e.g. "accepted", "rejected", "error", "device_unknown", "invalid_signature" etc. see /docs/errors.md for a list)
    timestamp: integer (Unix epoch seconds)
    server_signer_id: string (ID of the server's signing key, e.g. "server-key-1")
    server_signature: string (base64-encoded signature of the above fields using the server's signing key)

### Example

```json
{
  "entry_id": "5f4dcc3b5aa765d61d8327deb882cf99", // hash of the log entry being acknowledged (SHA-256 hex)
  "new_entry_hash": "6f1ed002ab5595859014ebf0951522d9", // hash of the new log entry being added (SHA-256 hex)
  "status": "accepted", // status of the acknowledgment (e.g. "accepted", "rejected", "error", etc.)
  "timestamp": 1700000050, // Unix epoch seconds
  "server_signer_id": "server-key-1", // ID of the server's signing key
  "server_signature": "MEUCIQDf...base64...IDAQAB" // base64-encoded signature of the above fields using the server's signing key
}
```

### Canonicalization for signing

We are using CBOR for canonicalization before signing, to ensure a stable binary representation of the ACK fields. The fields are serialized in the following order:
1. entry_id
2. new_entry_hash
3. status
4. timestamp
5. server_signer_id
(excluding the server_signature field)

The `server_signature` field is excluded from the canonicalization process as it is derived from the other fields and needs the canonicalized data to be generated.