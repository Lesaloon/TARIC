# Python Client (ctypes + C client lib)

This example shows how to call the C client library from Python to build a signed TARIC entry and send it to the demo server.

## Build the C client (shared lib)
```bash
make libtaric_client.so
```

## Install Python deps
```bash
pip install -r requirements.txt
```

## Run the example
```bash
python send_ctypes.py
```
