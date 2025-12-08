# Hardened Photo Server — Runbook

This runbook describes how to rebuild, run, test, debug, and evaluate the Hardened Photo Server inside the required Docker environment.

------------------------------------------------------------

## 1. Rebuild Instructions

### Full clean rebuild
Use this when resetting the environment or verifying a fresh clone build:

    make clean
    make up

This performs:
- Cleanup of old binaries and artifacts
- Docker image build (docker-build)
- Container startup (docker-run)

------------------------------------------------------------

## 2. Running the System

### Start the server

    make up

This:
- Builds the Docker image
- Starts the container as a non-root user
- Publishes the HTTPS port (default: 443)
- Prints the local access URL

Access UI:

    https://localhost

### Run the automated demo

    make demo

The demo:
- Waits for server readiness
- Fetches the index page
- Uploads a sample image
- Writes logs and metrics to artifacts/release/

------------------------------------------------------------

## 3. Running Tests

### Unit tests

    make unit-tests

### Integration tests (requires server running)

    make integration-tests

### Full test suite with coverage

    make test COVERAGE=1

Coverage output:

    *.gcov

GitHub Actions uploads these automatically.

------------------------------------------------------------

## 4. Evidence and Artifact Collection

All evaluation and security evidence is stored in:

    artifacts/release/

Contents may include:
- traffic.pcap
- server.log

### Capturing network traffic (PCAP)

In one terminal:

    docker run --rm -it    --net=container:hardened-photo-server    --cap-add=NET_ADMIN       -v "$(pwd)/artifacts/release/pcaps:/capture"       nicolaka/netshoot       tcpdump -i any port 443 -w /capture/traffic.pcap

In another terminal:

    make demo

Stop capture with Ctrl + C.

------------------------------------------------------------

## 5. Security Notes

- Server runs inside Docker as non-root user 'photo'
- Only sanitized filenames are accepted
- Only approved MIME types are stored
- Plaintext photos never leave the /photos directory
- HTTPS is enforced on all communication
- Logs include upload events and validation failures

------------------------------------------------------------

## 6. Troubleshooting

### Server fails to start
Ensure port is free. Check logs:

    docker logs hardened-photo-server

### Integration test failures
Ensure server is running:

    docker ps

### Empty PCAP
Ensure tcpdump is running before make demo.
Ensure correct port is used.

### Permission errors on test scripts

    chmod +x tests/*.sh

------------------------------------------------------------

## 7. Shutdown and Reset

### Stop container

    docker stop hardened-photo-server

### Remove container

    docker rm hardened-photo-server

### Remove image

    docker rmi hardened-photo-server

------------------------------------------------------------
