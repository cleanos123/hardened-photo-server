# Hardened Photo Server — Runbook
This runbook describes how to rebuild, run, test, debug, and evaluate the Hardened Photo Server inside the required Docker environment.  
All commands work on Linux, WSL2, and GitHub Actions runners.

---

#Rebuild Instructions

## Full clean rebuild
Use this when resetting the environment or verifying a fresh clone build:

```sh
make clean
make up
```