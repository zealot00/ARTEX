# artex-name: infra-redis-unauth-probe
# artex-severity: critical
# artex-tags: redis,database,unauth,infra,intranet
# artex-desc: Pure-TCP read-only probe checking whether Redis accepts unauthenticated PING / INFO server commands.
# artex-guidance: Report exact redis_version and OS line from INFO server; never run CONFIG SET / FLUSHALL / SAVE in production.
import os, socket, sys, urllib.parse

raw = os.environ.get("ARTEX_POC_TARGET", "").strip()
if not raw:
    print("ARTEX_POC_TARGET is required", file=sys.stderr)
    sys.exit(2)

host, port = raw, 6379
if "://" in raw:
    u = urllib.parse.urlsplit(raw)
    host = u.hostname or raw
    port = u.port or 6379
elif ":" in raw:
    h, p = raw.rsplit(":", 1)
    host = h.strip("[]")
    try:
        port = int(p)
    except ValueError:
        port = 6379

try:
    with socket.create_connection((host, port), timeout=5) as s:
        s.settimeout(5)
        s.sendall(b"PING\r\nINFO server\r\n")
        data = s.recv(4096).decode("utf-8", errors="ignore")
        if "+PONG" in data or "redis_version:" in data:
            lines = [ln for ln in data.splitlines() if ln.startswith("+PONG") or ln.startswith("redis_version:") or ln.startswith("os:")]
            print(f"CONFIRMED Redis unauthenticated access on {host}:{port}: " + " | ".join(lines[:4]))
            sys.exit(0)
        print(f"Redis authentication required or non-Redis response on {host}:{port}")
        sys.exit(1)
except Exception as e:
    print(f"Redis probe error on {host}:{port}: {e}")
    sys.exit(1)
