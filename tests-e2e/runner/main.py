import base64, json, os, time, uuid, requests
from nacl.signing import SigningKey
from nacl.encoding import RawEncoder
import cbor2

SERVER = os.environ.get("TARIC_SERVER", "http://server:8080")
ENTRY_COUNT = int(os.environ.get("ENTRY_COUNT", "0"))  # when >0, write N entries without assertions
TEST_MODE = os.environ.get("TEST_MODE", "default")      # default | per_session | ack_verify

def mk_entry(sk: SigningKey, device_id: str, key_id: str, payload: str, nonce: int, prev_hash: str|None, session_id: str|None = None):
	entry = {
		"version": 1,
		"entry_hash": "",
		"device_id": device_id,
		"timestamp": int(time.time()),
		"session_id": session_id or str(uuid.uuid4()),
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

def wait_for_health(url: str, timeout_s: int = 300):
	deadline = time.time() + timeout_s
	while time.time() < deadline:
		try:
			r = requests.get(url, timeout=2)
			if r.ok:
				return
		except Exception:
			pass
		time.sleep(1)
	raise RuntimeError("server not healthy in time")

def main():
	wait_for_health(f"{SERVER}/health", 300)
	# generate device keypair
	sk = SigningKey.generate()
	vk = sk.verify_key
	device_id = str(uuid.uuid4())
	key_id = "001-key1-1"
	write_fixture(device_id, base64.b64encode(bytes(vk)).decode(), key_id)

	if ENTRY_COUNT > 0:
		prev = None
		session = str(uuid.uuid4())
		for i in range(1, ENTRY_COUNT + 1):
			payload = json.dumps({"t": 20.0 + i/2})
			e = mk_entry(sk, device_id, key_id, payload, i, prev, session)
			print("Sending entry:", json.dumps(e))
			r = requests.post(f"{SERVER}/entries", json=e, timeout=5)
			r.raise_for_status()
			print("ACK:", r.json())
			prev = e["entry_hash"]
		print("Write-only mode complete")
		return
	elif TEST_MODE == "per_session":
		# session A: nonces 1,2 accepted
		prev = None
		session_a = str(uuid.uuid4())
		e1 = mk_entry(sk, device_id, key_id, json.dumps({"t":22.5}), 1, prev, session_a)
		a1 = requests.post(f"{SERVER}/entries", json=e1, timeout=5).json()
		assert a1["status"] == "accepted", a1
		prev = e1["entry_hash"]
		e2 = mk_entry(sk, device_id, key_id, json.dumps({"t":23.0}), 2, prev, session_a)
		a2 = requests.post(f"{SERVER}/entries", json=e2, timeout=5).json()
		assert a2["status"] == "accepted", a2
		# session B: fresh session can start at 1
		session_b = str(uuid.uuid4())
		e3 = mk_entry(sk, device_id, key_id, json.dumps({"t":24.0}), 1, e2["entry_hash"], session_b)
		a3 = requests.post(f"{SERVER}/entries", json=e3, timeout=5).json()
		assert a3["status"] == "accepted", a3
		print("per_session: PASS")
		return
	elif TEST_MODE == "ack_verify":
		# verify server_signature present on both accepted and error ACKs
		session = str(uuid.uuid4())
		e1 = mk_entry(sk, device_id, key_id, json.dumps({"t":22.5}), 1, None, session)
		a1 = requests.post(f"{SERVER}/entries", json=e1, timeout=5).json()
		assert a1["server_signature"], a1
		e2 = mk_entry(sk, device_id, key_id, json.dumps({"t":23.0}), 1, e1["entry_hash"], session)  # duplicate nonce to force error
		a2 = requests.post(f"{SERVER}/entries", json=e2, timeout=5).json()
		assert a2["status"].startswith("error:"), a2
		assert a2["server_signature"], a2
		print("ack_verify: PASS")
		return
	else:
		# post two chained entries with assertions
		session = str(uuid.uuid4())
		e1 = mk_entry(sk, device_id, key_id, "{\"t\":22.5}", 1, None, session)
		print("Sending entry:", json.dumps(e1))
		r1 = requests.post(f"{SERVER}/entries", json=e1, timeout=5)
		r1.raise_for_status()
		a1 = r1.json()
		print("ACK:", a1)
		assert a1["status"] == "accepted", a1

		e2 = mk_entry(sk, device_id, key_id, "{\"t\":23.0}", 2, e1["entry_hash"], session)
		print("Sending entry:", json.dumps(e2))
		r2 = requests.post(f"{SERVER}/entries", json=e2, timeout=5)
		r2.raise_for_status()
		a2 = r2.json()
		print("ACK:", a2)
		assert a2["status"] == "accepted", a2

		# replay with same nonce in same session should fail
		e_bad = mk_entry(sk, device_id, key_id, "{\"t\":24.0}", 2, e2["entry_hash"], session)
		print("Sending entry:", json.dumps(e_bad))
		r3 = requests.post(f"{SERVER}/entries", json=e_bad, timeout=5)
		r3.raise_for_status()
		a3 = r3.json()
		print("ACK:", a3)
		assert a3["status"].startswith("error:"), a3
		print("E2E: PASS")

if __name__ == "__main__":
	main()
