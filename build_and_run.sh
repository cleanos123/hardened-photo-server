#!/bin/sh
# build_and_run_httpsetup.sh
# OpenBSD-specific builder: installs deps, builds HTTPS server, runs it.

set -e

CERT="server.crt"
KEY="server.key"
SRC="httpsetup.c"
OUT="httpsetup"

echo "[*] OpenBSD: Checking and installing dependencies..."

# Required packages:
#   jpeg  - libjpeg with jpeglib.h
#   gmake - optional, but useful
PKGS="jpeg gmake"

for pkg in $PKGS; do
    if ! pkg_info -q "$pkg" >/dev/null 2>&1; then
        echo "[*] Installing package: $pkg"
        doas pkg_add "$pkg"
    else
        echo "[*] Package already installed: $pkg"
    fi
done

# Sanity check: make sure jpeglib.h exists
if [ ! -f /usr/local/include/jpeglib.h ]; then
    echo "[!] jpeglib.h not found under /usr/local/include."
    echo "    Make sure the 'jpeg' package installed correctly:"
    echo "    doas pkg_delete jpeg && doas pkg_add jpeg"
    exit 1
fi

echo "[*] All required packages are installed."

# -----------------------------
# 2. Generate certs if missing
# -----------------------------
if [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; then
    echo "[*] Generating self-signed certificate..."
    openssl req -x509 -newkey rsa:2048 \
        -keyout "$KEY" -out "$CERT" \
        -days 365 -nodes \
        -subj "/C=US/ST=None/L=None/O=SelfSigned/CN=localhost"
else
    echo "[*] Found existing certificate + key."
fi

# -----------------------------
# 3. Build the HTTPS server
# -----------------------------
echo "[*] Building HTTPS server..."

cc -O2 -pthread -Wall -Wextra \
   -I/usr/local/include \
   -L/usr/local/lib \
   -o "$OUT" "$SRC" \
   -lssl -lcrypto -ljpeg

echo "[*] Build successful."

# -----------------------------
# 4. Run the HTTPS server
# -----------------------------
echo "[*] Starting HTTPS server..."
./"$OUT"
