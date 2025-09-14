import base64, json, os, time, uuid, requests
from nacl.signing import SigningKey
from nacl.encoding import RawEncoder
import cbor2

SERVER = os.environ.get("TARIC_SERVER", "http://server:8080")

def mk_entry(sk: SigningKey, device_id: str, key_id: str, payload: str, nonce: int, prev_hash: str|None):
	entry = {
		"version": 1.0,
		"entry_hash": "",
		"device_id": device_id,
		"timestamp": int(time.time()),
		"session_id": str(uuid.uuid4()),
		"nonce": nonce,
		"algo": "ed25519",
		"key_id": key_id,
		"payload": payload,
		"signature": "",
		"previous_entry_hash": prev_hash,
	}
	# CBOR for hash
	to_hash = (
		entry["version"], entry["device_id"], entry["timestamp"], entry["session_id"], entry["nonce"],
		entry["algo"], entry["key_id"], entry["payload"], entry["previous_entry_hash"],
	)
	h = __import__("hashlib").sha256(cbor2.dumps(to_hash)).hexdigest()
	entry["entry_hash"] = h
	# CBOR for sign
	to_sign = (
		entry["version"], entry["entry_hash"], entry["device_id"], entry["timestamp"], entry["session_id"], entry["nonce"],
		entry["algo"], entry["key_id"], entry["payload"], entry["previous_entry_hash"],
	)
	sig = sk.sign(cbor2.dumps(to_sign), encoder=RawEncoder).signature
	entry["signature"] = base64.b64encode(sig).decode()
	return entry

def write_fixture(device_id: str, vk_b64: str, key_id: str):
	os.makedirs("/fixtures/devices", exist_ok=True)
	with open("/fixtures/devices/device.json", "w", encoding="utf-8") as f:
		json.dump({
			"device_id": device_id,
			"algo": "ed25519",
			"key_id": key_id,
			"pubkey_base64": vk_b64,
		}, f)

def main():
	# generate device keypair
	sk = SigningKey.generate()
	vk = sk.verify_key
	device_id = str(uuid.uuid4())
	key_id = "001-key1-1"
	write_fixture(device_id, base64.b64encode(bytes(vk)).decode(), key_id)

	# post two chained entries
	e1 = mk_entry(sk, device_id, key_id, "{\"t\":22.5}", 1, None)
	r1 = requests.post(f"{SERVER}/entries", json=e1, timeout=5)
	r1.raise_for_status()
	a1 = r1.json()
	assert a1["status"] == "accepted", a1

	e2 = mk_entry(sk, device_id, key_id, "{\"t\":23.0}", 2, e1["entry_hash"])
	r2 = requests.post(f"{SERVER}/entries", json=e2, timeout=5)
	r2.raise_for_status()
	a2 = r2.json()
	assert a2["status"] == "accepted", a2

	# replay with old nonce should fail
	e_bad = mk_entry(sk, device_id, key_id, "{\"t\":24.0}", 2, e2["entry_hash"])
	r3 = requests.post(f"{SERVER}/entries", json=e_bad, timeout=5)
	r3.raise_for_status()
	a3 = r3.json()
	assert a3["status"].startswith("error:"), a3
	print("E2E: PASS")

if __name__ == "__main__":
	main()
