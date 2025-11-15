# Makefile for Hardened Photo Server (OpenBSD edition)
# =====================================================
# Usage:
#   make bootstrap   -> install dependencies
#   make build       -> compile the server
#   make run         -> run the server
#   make clean       -> remove build artifacts

# --- Variables ---
CC      ?= cc
CFLAGS  = -O2 -Wall -Wextra -std=c11
SRC     = src/server.c
BIN     = server

# --- Targets ---
.PHONY: all bootstrap build run clean

all: build

bootstrap:
	@echo "==> Bootstrapping environment..."
	@echo "Installing build tools (requires doas/sudo)..."
	doas pkg_add gcc gmake || true
	doas pkg_add libjpeg || true
	doas mkdir -p /srv/photos
	doas chown _www:_www /srv/photos
	@echo "==> Environment ready!"

build:
	@echo "==> Building Hardened Photo Server..."
	$(CC) $(CFLAGS) $(SRC) -o $(BIN)
	@echo "==> Build complete: ./$(BIN)"

run: build
	@echo "==> Starting Hardened Photo Server on http://localhost:8080"
	doas -u _www ./$(BIN)

clean:
	rm -f $(BIN) *.o
	@echo "==> Cleaned up build files."
