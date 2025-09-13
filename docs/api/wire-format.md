# TARIC Wire Format (draft)

## Log Entry
device_id, timestamp, nonce, algo, key_id, payload, signature

## ACK
entry_id, previous_hash, new_entry_hash, status, timestamp, server_signer_id, server_signature
