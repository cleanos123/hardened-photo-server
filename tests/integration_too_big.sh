#!/bin/sh
set -e
. "$(dirname "$0")/integration_common.sh"

BASE_URL="${BASE_URL:-https://localhost:443}"

wait_for_server

echo "[int] negative: oversized upload (expect 413)"

# 210 MB stream (MAX_UPLOAD is 200 MB)
SIZE_MB=210

HTTP_CODE=$(dd if=/dev/zero bs=1M count=$SIZE_MB 2>/dev/null | \
  curl -k -s -o /dev/null -w "%{http_code}" \
    -X POST "$BASE_URL/upload-raw" \
    -H "Content-Type: application/octet-stream" \
    -H "X-Filename: huge.bin" \
    --data-binary @- || true)

echo "[int] got HTTP $HTTP_CODE"

if [ "$HTTP_CODE" = "413" ]; then
  echo "[int] negative oversized upload passed (got 413)."
else
  echo "[int] expected 413, got $HTTP_CODE"
  exit 1
fi
