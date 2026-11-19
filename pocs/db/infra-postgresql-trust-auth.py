# artex-name: infra-postgresql-trust-auth
# artex-severity: critical
# artex-tags: postgresql,postgres,database,unauth,infra,intranet
# artex-desc: Pure-TCP PostgreSQL wire-protocol startup probe checking whether :5432 accepts trust (passwordless) authentication for user 'postgres'.
# artex-guidance: Replace 'trust' with 'scram-sha-256' in pg_hba.conf and restrict listen_addresses.
import os, socket, struct, sys, urllib.parse

raw = os.environ.get("ARTEX_POC_TARGET", "").strip()
if not raw:
    print("ARTEX_POC_TARGET is required", file=sys.stderr)
    sys.exit(2)

host, port = raw, 5432
if "://" in raw:
    u = urllib.parse.urlsplit(raw)
    host = u.hostname or raw
    port = u.port or 5432
elif ":" in raw:
    h, p = raw.rsplit(":", 1)
    host = h.strip("[]")
    try:
        port = int(p)
    except ValueError:
        port = 5432

# PostgreSQL v3.0 StartupMessage: length(4) + protocol(196608) + params + \x00
params = b"user\x00postgres\x00database\x00postgres\x00\x00"
startup = struct.pack("!II", 8 + len(params), 196608) + params

try:
    with socket.create_connection((host, port), timeout=5) as s:
        s.settimeout(5)
        s.sendall(startup)
        resp = s.recv(1024)
        if len(resp) >= 9 and resp[0:1] == b"R":
            auth_code = struct.unpack("!I", resp[5:9])[0]
            if auth_code == 0:
                print(f"CONFIRMED PostgreSQL trust (passwordless) auth for user 'postgres' on {host}:{port}")
                sys.exit(0)
            print(f"PostgreSQL on {host}:{port} requires auth (auth_type={auth_code})")
            sys.exit(1)
        print(f"Unexpected PostgreSQL response on {host}:{port}")
        sys.exit(1)
except Exception as e:
    print(f"PostgreSQL probe error on {host}:{port}: {e}")
    sys.exit(1)
