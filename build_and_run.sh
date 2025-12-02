#!/bin/sh
# build_and_run_httpsetup.sh
# Checks for cert/key, builds the HTTPS server, then runs it.

CERT="server.crt"
KEY="server.key"
SRC="httpsetup.c"
OUT="httpsetup"

# 1. Check if cert/key exist; if not, generate self-signed ones
if [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; then
    echo "[*] Generating self-signed certificate..."
    openssl req -x509 -newkey rsa:2048 -keyout "$KEY" -out "$CERT" -days 365 -nodes \
        -subj "/C=US/ST=None/L=None/O=SelfSigned/CN=localhost"
else
    echo "[*] Found existing certificate and key."
fi

# 2. Compile the HTTPS server
echo "[*] Compiling..."
egcc -O2 -pthread -Wall -Wextra -o "$OUT" "$SRC" -lssl -lcrypto -ljpeg
if [ $? -ne 0 ]; then
    echo "[!] Build failed."
    exit 1
fi
echo "[*] Build successful."

# 3. Run it
echo "[*] Starting HTTPS server..."
./"$OUT"
