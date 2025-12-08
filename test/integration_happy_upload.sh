#!/bin/sh
set -e
. "$(dirname "$0")/integration_common.sh"

BASE_URL="${BASE_URL:-https://localhost:443}"

wait_for_server

echo "[int] happy-path: upload small jpeg"
# create a tiny fake jpeg if none exists
if [ ! -f tests/demo.jpg ]; then
  # 1x1 black JPEG from /dev/zerowrapped via printf header; but simplest is just reuse any small jpg in repo
  cp index.html tests/demo.jpg 2>/dev/null || echo "fake" > tests/demo.jpg
fi

HTTP_CODE=$(curl -k -s -o /dev/null -w "%{http_code}" \
  -X POST "$BASE_URL/upload-raw" \
  -H "Content-Type: application/octet-stream" \
  -H "X-Filename: demo.jpg" \
  --data-binary @tests/demo.jpg)

echo "[int] got HTTP $HTTP_CODE"
test "$HTTP_CODE" = "200" || { echo "[int] EXPECT 200"; exit 1; }

echo "[int] happy-path upload passed."
