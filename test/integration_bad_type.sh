#!/bin/sh
set -e
. "$(dirname "$0")/integration_common.sh"

BASE_URL="${BASE_URL:-https://localhost:443}"

wait_for_server

echo "[int] negative: bad Content-Type"

HTTP_CODE=$(printf "hello" | curl -k -s -o /dev/null -w "%{http_code}" \
  -X POST "$BASE_URL/upload-raw" \
  -H "Content-Type: text/plain" \
  -H "X-Filename: bad.txt" \
  --data-binary @-)

echo "[int] got HTTP $HTTP_CODE"
# expect rejection (415 or 400 or 500 depending on your handler)
case "$HTTP_CODE" in
  4*|5*) echo "[int] negative bad type passed." ;;
  *) echo "[int] expected failure status, got $HTTP_CODE"; exit 1 ;;
esac
