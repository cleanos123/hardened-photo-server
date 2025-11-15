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
	@echo "Bootstrap not implemented yet"

build:
	@echo "Build command not implemeneted yet"

run: build
	@echo "Build run command not implemeneted yet"

clean:
	rm -f $(BIN) *.o
	@echo "==> Cleaned up build files."
