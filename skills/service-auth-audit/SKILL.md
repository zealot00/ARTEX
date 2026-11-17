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

## 4. Low-Rate Weak Credential Audit (`AUTH-WEAKPWD`)
- Always keep concurrency low (`-t 4`) and use a small curated default-credential list (`admin/admin`, `root/root`, `test/123456`, etc.) so accounts do not lock out:
  `hydra -L users.txt -P pass.txt -t 4 -f <service>://<host>`
- Record every tested service target via `record_check_result(check_code="AUTH-WEAKPWD", status="passed"|"failed", target=..., evidence=...)`.
