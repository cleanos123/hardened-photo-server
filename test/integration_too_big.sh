#!/bin/sh
set -e
. "$(dirname "$0")/integration_common.sh"

BASE_URL="${BASE_URL:-https://localhost:443}"

wait_for_server

echo "[int] negative: oversized upload"

# 210MB stream (bigger than MAX_UPLOAD 200MB)
SIZE=$((210 * 1024 * 1024))

HTTP_CODE=$(dd if=/dev/zero bs=1M count=210 2>/dev/null | \
  curl -k -s -o /dev/null -w "%{http_code}" \
    -X POST "$BASE_URL/upload-raw" \
    -H "Content-Type: application/octet-stream" \
    -H "X-Filename: huge.bin" \
    --data-binary @- || true)

echo "[int] got HTTP $HTTP_CODE"
case "$HTTP_CODE" in
  4*|5*) echo "[int] negative oversized passed." ;;
  *) echo "[int] expected failure status, got $HTTP_CODE"; exit 1 ;;
esac
