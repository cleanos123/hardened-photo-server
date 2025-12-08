#!/bin/sh
set -e
. "$(dirname "$0")/integration_common.sh"

BASE_URL="${BASE_URL:-https://localhost:443}"

wait_for_server

echo "[int] negative: bad Content-Type (text/plain instead of image/* or octet-stream)"

HTTP_CODE=$(printf "hello" | curl -k -s -o /dev/null -w "%{http_code}" \
  -X POST "$BASE_URL/upload-raw" \
  -H "Content-Type: text/plain" \
  -H "X-Filename: bad.txt" \
  --data-binary @-)

echo "[int] got HTTP $HTTP_CODE"

if [ "$HTTP_CODE" = "415" ]; then
  echo "[int] negative bad Content-Type passed (got 415)."
else
  echo "[int] expected 415, got $HTTP_CODE"
  exit 1
fi
