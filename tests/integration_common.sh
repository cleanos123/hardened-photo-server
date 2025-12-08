#!/bin/sh
set -e

BASE_URL="${BASE_URL:-https://localhost:443}"
AUTH_COOKIE_HEADER="Cookie: auth=1"

wait_for_server() {
  echo "[int] waiting for server at $BASE_URL..."
  for i in 1 2 3 4 5 6 7 8 9 10; do
    if curl -k -s -o /dev/null "$BASE_URL/"; then
      echo "[int] server is up."
      return 0
    fi
    sleep 1
  done
  echo "[int] server did not come up in time."
  return 1
}
