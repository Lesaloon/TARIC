# TARIC Context (summary)

TARIC = Tamper-Resistant IoT Chain.
- Device signs entries; server verifies + chains.
- ACKs are signed by server (optional) and let device confirm inclusion.
- Enrollment is out-of-scope: dev supplies a trust source (e.g., static JSON, PKI, TOFU).
See `docs/api/wire-format.md` for envelopes.
