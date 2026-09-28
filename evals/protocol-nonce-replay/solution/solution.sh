#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

python3 - <<'PY'
import hmac, hashlib, re, pathlib, subprocess, sys

res = pathlib.Path("resources")
log = (res / "exchange.log").read_text()
m = re.search(r"NONCE=(\w+)\s+DATA=(\w+)\s*\n\[client\] RESPONSE=(\w+)\s*\n\[server\] OK", log)
if not m:
    raise SystemExit("no successful exchange found")
nonce, data, resp = m.group(1), m.group(2), m.group(3)

secret = None
for w in (res / "wordlist.txt").read_text().split():
    if hmac.new(w.encode(), f"{nonce}|{data}".encode(), hashlib.sha256).hexdigest() == resp:
        secret = w
        break
if secret is None:
    raise SystemExit("secret not found in wordlist")

ch = (res / "challenge.txt").read_text()
n = re.search(r"NONCE=(\w+)", ch).group(1)
d = re.search(r"DATA=(\w+)", ch).group(1)
new_resp = hmac.new(secret.encode(), f"{n}|{d}".encode(), hashlib.sha256).hexdigest()

out = subprocess.check_output([sys.executable, str(res / "verify.py"), n, d, new_resp], text=True).strip()
assert out == "OK", f"verify.py said: {out}"
print("FLAG{nonce_hmac_recovered}")
PY