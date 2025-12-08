#!/bin/sh
set -e
. "$(dirname "$0")/integration_common.sh"

BASE_URL="${BASE_URL:-https://localhost:443}"

wait_for_server

echo "[int] happy-path: GET / (home page)"

HTTP_CODE=$(curl -k -s -o /dev/null -w "%{http_code}" \
  "$BASE_URL/")

echo "[int] got HTTP $HTTP_CODE"

if [ "$HTTP_CODE" = "200" ]; then
  echo "[int] happy-path home page passed."
else
  echo "[int] expected 200, got $HTTP_CODE"
  exit 1
fi
