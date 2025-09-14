import ctypes as ct, json, os, requests

# Configure server
SERVER = os.environ.get("TARIC_SERVER", "http://127.0.0.1:8080")

# Load C client shared lib
lib_path = os.environ.get("TARIC_C_LIB", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "clients", "c", "libtaric_client.so")))
lib = ct.CDLL(lib_path)

class TaricClientCfg(ct.Structure):
    _fields_ = [
        ("device_id", ct.c_char_p),
        ("sign_algo", ct.c_char_p),
        ("key_id", ct.c_char_p),
        ("verify_server_ack", ct.c_int),
    ]

# Configure function prototypes
lib.taric_build_signed_entry.argtypes = [ct.POINTER(TaricClientCfg), ct.POINTER(ct.c_uint8), ct.c_size_t, ct.c_char_p, ct.c_char_p, ct.POINTER(ct.c_uint8), ct.POINTER(ct.c_size_t)]
lib.taric_build_signed_entry.restype = ct.c_int
lib.taric_verify_ack.argtypes = [ct.POINTER(TaricClientCfg), ct.POINTER(ct.c_uint8), ct.c_size_t]
lib.taric_verify_ack.restype = ct.c_int

cfg = TaricClientCfg(
    device_id=b"example-device",
    sign_algo=b"ed25519",
    key_id=b"001-key1-1",
    verify_server_ack=0,
)

payload = b'{"t": 22.5}'
out_buf = (ct.c_uint8 * 4096)()
out_len = ct.c_size_t(len(out_buf))

rc = lib.taric_build_signed_entry(ct.byref(cfg), payload, len(payload), cfg.sign_algo, cfg.key_id, out_buf, ct.byref(out_len))
if rc != 0:
    raise RuntimeError(f"taric_build_signed_entry failed: {rc}")

entry_json = bytes(out_buf[:out_len.value]).decode()
try:
    entry = json.loads(entry_json)
except Exception:
    # C stub outputs a placeholder; fall back to a simple unsiged demo payload
    entry = {
        "version": 1.0,
        "entry_hash": "",
        "device_id": cfg.device_id.decode(),
        "timestamp": 0,
        "session_id": "00000000-0000-0000-0000-000000000000",
        "nonce": 1,
        "algo": "none",
        "key_id": cfg.key_id.decode(),
        "payload": payload.decode(),
        "signature": "",
        "previous_entry_hash": None,
    }

r = requests.post(f"{SERVER}/entries", json=entry, timeout=5)
print("Response:", r.status_code, r.text)