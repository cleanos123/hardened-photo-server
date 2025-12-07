# Makefile for Hardened Photo Server
# =================================
# Common targets:
#   make bootstrap   -> install deps on Debian/Ubuntu (if run as root)
#   make build       -> compile httpsetup locally
#   make run         -> run httpsetup locally (generates certs if needed)
#   make clean       -> remove build artifacts
#
#   make docker-build -> build Docker image
#   make docker-run   -> run Docker container
#   make up           -> docker-build + docker-run
#   make demo         -> simple curl-based demo against the running container

# ---- Configurable vars ----
CC          ?= gcc
CFLAGS      ?= -O2 -Wall -Wextra -std=c11 -pthread
LIBS        ?= -lssl -lcrypto -ljpeg -lpthread

SRC         := httpsetup.c
BIN         := httpsetup

# Default port & photos directory
PORT        ?= 443
PHOTOS_DIR  ?= /photos

# Docker settings
IMAGE_NAME      ?= hardened-photo-server
CONTAINER_NAME  ?= hardened-photo-server

# Add compile-time defines
CFLAGS += -DPORT=$(PORT) -DPHOTOS_DIR=\"$(PHOTOS_DIR)\"

.PHONY: all bootstrap build run clean docker-build docker-run up demo

all: build

# ---- Bootstrap: install deps on Debian/Ubuntu if possible ----
bootstrap:
	@echo "==> Bootstrapping build environment (Debian/Ubuntu only)..."
	@if command -v apt-get >/dev/null 2>&1; then \
		if [ "$$(id -u)" -eq 0 ]; then \
			echo "Installing: build-essential libssl-dev libjpeg-dev openssl make"; \
			apt-get update && \
			apt-get install -y --no-install-recommends \
				build-essential libssl-dev libjpeg-dev openssl make; \
		else \
			echo "Not running as root; please run:"; \
			echo "  sudo apt-get update"; \
			echo "  sudo apt-get install build-essential libssl-dev libjpeg-dev openssl make"; \
		fi \
	else \
		echo "apt-get not found. Please install manually:"; \
		echo "  - C compiler (gcc/clang)"; \
		echo "  - make"; \
		echo "  - libssl-dev (or equivalent)"; \
		echo "  - libjpeg-dev (or equivalent)"; \
		echo "  - openssl (command-line tool)"; \
	fi

# ---- Local build/run ----
build: $(BIN)

$(BIN): $(SRC)
	@echo "==> Building $(BIN) (PORT=$(PORT), PHOTOS_DIR=$(PHOTOS_DIR))"
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

run: build
	@echo "==> Ensuring photos directory exists: $(PHOTOS_DIR)"
	mkdir -p "$(PHOTOS_DIR)"
	@if [ ! -f server.crt ] || [ ! -f server.key ]; then \
		echo "==> Generating self-signed TLS certificate..."; \
		openssl req -x509 -newkey rsa:2048 \
			-keyout server.key -out server.crt \
			-days 365 -nodes \
			-subj "/C=US/ST=None/L=None/O=SelfSigned/CN=localhost"; \
	else \
		echo "==> Using existing server.crt/server.key"; \
	fi
	@echo "==> Starting HTTPS server on port $(PORT)..."
	./$(BIN)

clean:
	@echo "==> Cleaning build artifacts"
	rm -f $(BIN) *.o *.gcda *.gcno *.gcov

# ---- Docker targets ----

docker-build:
	@echo "==> Building Docker image '$(IMAGE_NAME)' (PORT=$(PORT))"
	docker build \
		--build-arg PORT=$(PORT) \
		--build-arg PHOTOS_DIR=/photos \
		-t $(IMAGE_NAME) .

docker-run:
	@echo "==> Running container '$(CONTAINER_NAME)' on host port $(PORT)"
	-@docker rm -f $(CONTAINER_NAME) >/dev/null 2>&1 || true
	docker run -d --name $(CONTAINER_NAME) \
		-p $(PORT):$(PORT) \
		$(IMAGE_NAME)

# Main entrypoint for the assignment
up: docker-build docker-run
	@echo "==> Container is up. Visit: https://localhost:$(PORT)/ (self-signed cert)"

# Very simple demo: hit the index page, and (optionally) upload demo.jpg
demo:
	@echo "==> Running demo against https://localhost:$(PORT)"
	@sleep 3
	@echo "==> Fetching index page..."
	@curl -k -s -o /dev/null -w "HTTP %{http_code}\n" https://localhost:$(PORT)/ || true
	@if [ -f demo.jpg ]; then \
		echo "==> demo.jpg found. Uploading via /upload-raw..."; \
		curl -k -s -o /dev/null -w "HTTP %{http_code}\n" \
			-X POST "https://localhost:$(PORT)/upload-raw" \
			-H "Content-Type: application/octet-stream" \
			-H "X-Filename: demo.jpg" \
			--data-binary @demo.jpg; \
	else \
		echo "==> (Optional) Place a valid JPEG named 'demo.jpg' in the repo root to test upload."; \
	fi
	@echo "==> Demo complete."
