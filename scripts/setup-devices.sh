#!/usr/bin/env bash
set -euo pipefail

# Generates tests-e2e/fixtures/devices/devices.json (array) and device.json (single)
# Each entry contains: device_id, algo, key_id, pubkey_base64
# Requires Python 3 with pynacl installed (pip install pynacl)

ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
FIX_DIR="$ROOT_DIR/tests-e2e/fixtures/devices"
mkdir -p "$FIX_DIR"

DEVICE_ID=${DEVICE_ID:-}
KEY_ID=${KEY_ID:-"001-key1-1"}

python - <<'PY'
import os, sys, json, base64, uuid
try:
    from nacl.signing import SigningKey
except ImportError:
    print("Missing 'pynacl'. Install with: pip install pynacl", file=sys.stderr)
    sys.exit(2)

root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
fix_dir = os.path.join(root, 'tests-e2e', 'fixtures', 'devices')
os.makedirs(fix_dir, exist_ok=True)

device_id = os.environ.get('DEVICE_ID') or str(uuid.uuid4())
key_id = os.environ.get('KEY_ID') or '001-key1-1'

sk = SigningKey.generate()
vk = sk.verify_key

entry = {
  'device_id': device_id,
  'algo': 'ed25519',
  'key_id': key_id,
  'pubkey_base64': base64.b64encode(bytes(vk)).decode('ascii'),
}

# Write devices.json (array)
devices_path = os.path.join(fix_dir, 'devices.json')
if os.path.exists(devices_path):
    try:
        with open(devices_path, 'r', encoding='utf-8') as f:
            arr = json.load(f)
            if not isinstance(arr, list):
                arr = []
    except Exception:
        arr = []
else:
    arr = []

# Remove any existing entry with same device_id
arr = [d for d in arr if d.get('device_id') != device_id]
arr.append(entry)
with open(devices_path, 'w', encoding='utf-8') as f:
    json.dump(arr, f, indent=2)

# Also write single device.json for compatibility
with open(os.path.join(fix_dir, 'device.json'), 'w', encoding='utf-8') as f:
    json.dump(entry, f, indent=2)

print("Wrote:")
print(" -", devices_path)
print(" -", os.path.join(fix_dir, 'device.json'))
print("Device:", entry['device_id'], "Key ID:", entry['key_id'])
PY
