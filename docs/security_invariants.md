# Security Invariants — Hardened Photo Server

This document defines the core security guarantees and constraints the system must uphold at all times.

------------------------------------------------------------

## 1. Privilege and Isolation

1. The server must run as a non-root user inside the Docker container.
2. The application may not perform privileged operations or write outside the allowed directories.
3. No component should execute arbitrary external programs.

------------------------------------------------------------

## 2. File Handling and Data Integrity

1. Plaintext images must never be written outside the designated /photos directory.
2. Filenames must be sanitized to prevent directory traversal or injection.
3. Only valid MIME types should be accepted.
4. The server must reject files that exceed defined limits.

------------------------------------------------------------

## 3. Network and Transport Security

1. All client communication must occur over HTTPS.
2. The server must not expose non-TLS endpoints.
3. Only the intended port (8443 by default) may be published externally.

------------------------------------------------------------

## 4. Logging and Observability

1. Logs must record key security events such as failed validations and rejected uploads.
2. Logs must not contain sensitive image data or plaintext beyond minimal diagnostic detail.
3. Metrics must reflect operational accuracy and not reveal confidential content.

------------------------------------------------------------

## 5. Container and Runtime Restrictions

1. The container filesystem must remain read-only except for the photos directory and necessary runtime temp directories.
2. No secrets may be embedded directly in the image.
3. The server must not escalate privileges or modify system-level configurations.

------------------------------------------------------------

## 6. Behavior Under Failure

1. Invalid or malformed input must result in rejection, not partial execution.
2. Unexpected internal errors must not expose sensitive data to clients.
3. The server must fail closed, not open, during TLS or validation failures.

------------------------------------------------------------

