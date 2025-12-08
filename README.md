# hardened-photo-server
A hardened, self-hosted photo upload and gallery server written in **C**, demonstrating secure systems programming practices including:

- HTTPS with OpenSSL  
- Privilege separation  
- Strict upload validation  
- JPEG sanitization  
- Logging & observability  
- Containerized deployment (Docker)  

The system can run end-to-end with:

```bash
make up && make demo
```

---

# Features

- Fully custom HTTPS server (no external web server required)
- Secure image upload pipeline:
  - Content-Length enforcement
  - Filename sanitization
  - MIME sniffing
  - JPEG validation & re-encode via libjpeg
  - Corrupt/unsafe files rejected
- Static HTML gallery UI
- Asynchronous logging thread
- Metrics export capability
- Runs as **unprivileged user** inside Docker
- Self-contained, reproducible deployment
---

# Running the Server (Windows • macOS • Linux • OpenBSD)

The recommended method is **Docker**, so the server always runs in a hardened Linux container.

---

## Windows (Docker Desktop)

### **Prerequisites**
1. Install **Docker Desktop for Windows**  
2. Install **Git for Windows**  (or clone this repo)
3. Install `make` (via Scoop or Git for Windows tools)

### **Run**
```bash
git clone https://github.com/cleanos123/hardened-photo-server.git
cd hardened-photo-server

make up        # build image + start container
make demo      # optional automated curl test
```

Open your browser:

```
https://localhost
```

Accept the self-signed certificate.

---

## macOS (Docker Desktop)

### **Prerequisites**
```bash
brew install git make
```

### **Run**
```bash
git clone https://github.com/cleanos123/hardened-photo-server.git
cd hardened-photo-server

make up
make demo
```

Browse to:

```
https://localhost
```

---

## Linux (Ubuntu / Debian / Fedora / Arch)

### **Install Docker**

**Ubuntu / Debian**
```bash
sudo apt update
sudo apt install docker.io git make
sudo systemctl enable --now docker
```

**Fedora**
```bash
sudo dnf install docker git make
sudo systemctl enable --now docker
```

**Arch**
```bash
sudo pacman -S docker git make
sudo systemctl enable --now docker
```

### **Run**
```bash
git clone https://github.com/cleanos123/hardened-photo-server.git
cd hardened-photo-server

make up
make demo
```

Browse:

```
https://localhost:
```

---

## OpenBSD (advanced users)

OpenBSD does **not support Docker natively**, so we will run on the OS itself.

**Please look up a tutorial on how to install openbsd as it will be its own seperate thing:**

LINK:https://www.youtube.com/watch?v=07rSLK_zW-s&t

**Highly Recommend using ssh to do these steps as openbsd configuration is annoying to deal with**

Make sure to install git and htop(other dependencies will be installed).

Commands to run
```bash
doas git clone https://github.com/cleanos123/hardened-photo-server.git
cd hardened-photo-server
doas chmod +x ./build_and_run.sh
doas ./build_and_run.sh
```
---

# Stopping & Removing the Container

Stop the running server:

```bash
docker stop hardened-photo-server
```

Remove the container:

```bash
docker rm -f hardened-photo-server
```

(Optional) Clean unused Docker images:

```bash
docker system prune -a
```

---

# Development (optional local build)

If you want to build the C server *without* Docker:

### Linux or WSL:

```bash
sudo apt install build-essential libssl-dev libjpeg-dev openssl
make build
make run
```

OpenBSD uses:

```sh
pkg_add jpeg gmake
./build_and_run_httpsetup.sh
```

---
---
#Running tests
```bash
make clean
make test COVERAGE=1
gcov httpsetup.c
```
---
# Architecture Summary

```
+-------------------------------------------------------------+
| HTTPS Frontend (C)                                          |
|  • TLS termination                                          |
|  • GET: static UI / gallery                                 |
|  • POST /upload-raw: upload pipeline                        |
|                                                             |
| Upload Pipeline                                             |
|  • Enforce Content-Length                                   |
|  • Sanitize filenames                                       |
|  • Validate JPEG structure (libjpeg)                        |
|  • Re-encode to safe form                                   |
|  • Reject malformed files                                   |
|                                                             |
| Storage Layer                                               |
|  • /photos directory                                        |
|  • timestamped sanitized filenames                          |
|                                                             |
| Logging Layer                                               |
|  • Async logging thread                                     |
|  • Upload events, errors, security logs                     |
|                                                             |
+-------------------------------------------------------------+
```

---

# Project Structure

```
/app
  httpsetup.c                 # HTTPS server & upload pipeline
  Dockerfile                 # Containerized build/deploy
  Makefile                   # make up, make demo, etc.
  build_and_run_httpsetup.sh # BSD build script (optional)
  html/                      # frontend UI

/artifacts/release/
  pcaps/
  metrics.json
  metrics.csv
  logs/
  charts/

/docs
  ARCHITECTURE.md
  RUNBOOK.md
  SECURITY.md
  what-works-whats-next.md
```

---

# License

BSD 2-Clause License


LINK FOR REFERENCE:
https://youtu.be/wAMsyb0K2jE
