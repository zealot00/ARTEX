---
name: service-auth-audit
description: Safe weak-credential and unauthenticated-access auditing for SSH, SMB, Redis, MySQL, PostgreSQL, FTP, and TLS services using preinstalled CLI tools.
---

# Service Authentication & Protocol Audit

Use this skill for MLPS checks `AUTH-WEAKPWD`, `SVC-UNAUTH`, and `NET-TLS`.

## 1. Service Discovery
- Enumerate open TCP ports and banners first:
  `nmap -sV -Pn --top-ports 1000 <target>` (keep timing `-T3` in production).

## 2. TLS & Cipher Audit (`NET-TLS`)
- Run `sslscan --no-colour <host>:<port>` to check for SSLv3 / TLS 1.0 / TLS 1.1, weak ciphers (RC4, 3DES, NULL, EXPORT), expired/self-signed certs.
- If all checks pass (TLS 1.2/1.3 only, strong AEAD ciphers), record `record_check_result(check_code="NET-TLS", status="passed", ...)`.

## 3. Unauthenticated Service Checks (`SVC-UNAUTH`)
- **Redis (6379)**: `redis-cli -h <host> -p 6379 ping` (expect `NOAUTH` or auth error; `PONG` without auth = finding).
- **SMB (445)**: `smbclient -L //<host> -N` (check anonymous share listing).
- **PostgreSQL (5432)**: `PGCONNECT_TIMEOUT=5 psql -h <host> -U postgres -c "SELECT version();"` (check trust auth / default creds).
- **MySQL (3306)**: `mysql --connect-timeout=5 -h <host> -u root -e "SELECT VERSION();"` (check empty password).

## 4. Encrypted Model-Opaque Credential Audit (`AUTH-WEAKPWD`)
- **NEVER** create plaintext password lists in the workspace or run `hydra -L/-P` against local plaintext dictionary files when server-side encrypted wordlists are available.
- First call `list_wordlists()` to inspect available encrypted wordlists (metadata only: `id`, `name`, `kind`, `entry_count`).
- Run `run_credential_audit(task_id=..., target=..., service=..., port=..., user_list=..., pass_list=..., threads=4)` (or `username=...` / `userpass_list=...`).
  - Plaintext entries are decrypted only in an ephemeral `0700` temp directory outside the workspace and deleted immediately after execution.
  - Electronic fence (`fence_enabled`) and `prod_safe_mode` concurrency cap (`<= 4` threads) are enforced automatically, and matched passwords are masked in tool output so plaintext passwords never enter model context.
- Record every tested service target via `record_check_result(check_code="AUTH-WEAKPWD", status="passed"|"failed", target=..., evidence=...)`.
