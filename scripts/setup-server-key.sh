#!/usr/bin/env bash
set -euo pipefail

# Generate an Ed25519 server signing key and write it to fixtures
# Requires: python3 + pynacl

ROOT_DIR="$(cd "${BASH_SOURCE[0]%/*}"/.. && pwd)"
FIXTURES_DIR="$ROOT_DIR/tests-e2e/fixtures/server"
FILE="$FIXTURES_DIR/server_key.json"

mkdir -p "$FIXTURES_DIR"

python3 - "$FILE" <<'PY'
import base64, json, sys
from nacl.signing import SigningKey

out = sys.argv[1]
sk = SigningKey.generate()
seed = bytes(sk)  # 32-byte seed
rec = {
  "signer_id": "server-key-1",
  "algo": "ed25519",
  "secret_key_base64": base64.b64encode(seed).decode(),
}
with open(out, 'w', encoding='utf-8') as f:
    json.dump(rec, f)
print("wrote", out)
PY

# Show where to point the server
echo "Server will read key from: $FILE"
echo "You can also set TARIC_SERVER_KEY_PATH to override."
