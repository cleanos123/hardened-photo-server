#!/bin/sh
set -e
. "$(dirname "$0")/integration_common.sh"

BASE_URL="${BASE_URL:-https://localhost:443}"

wait_for_server

echo "[int] happy-path: upload small jpeg"

# Simple tiny payload; you can swap in a real jpg if you like
if [ ! -f tests/demo.jpg ]; then
  printf '\xff\xd8\xff\xd9' > tests/demo.jpg   # minimal JPEG
fi

HTTP_CODE=$(curl -k -s -o /dev/null -w "%{http_code}" \
  -X POST "$BASE_URL/upload-raw" \
  -H "Content-Type: application/octet-stream" \
  -H "X-Filename: demo.jpg" \
  --data-binary @tests/demo.jpg)

echo "[int] got HTTP $HTTP_CODE"

if [ "$HTTP_CODE" = "200" ]; then
  echo "[int] happy-path upload passed."
else
  echo "[int] expected 200, got $HTTP_CODE"
  exit 1
fi
