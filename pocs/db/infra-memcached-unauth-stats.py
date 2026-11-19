# artex-name: infra-memcached-unauth-stats
# artex-severity: high
# artex-tags: memcached,database,unauth,infra,intranet
# artex-desc: Pure-TCP read-only probe checking whether Memcached (:11211) accepts unauthenticated 'stats' command.
# artex-guidance: Bind Memcached to 127.0.0.1 or enforce SASL authentication / internal firewall isolation.
import os, socket, sys, urllib.parse

raw = os.environ.get("ARTEX_POC_TARGET", "").strip()
if not raw:
    print("ARTEX_POC_TARGET is required", file=sys.stderr)
    sys.exit(2)

host, port = raw, 11211
if "://" in raw:
    u = urllib.parse.urlsplit(raw)
    host = u.hostname or raw
    port = u.port or 11211
elif ":" in raw:
    h, p = raw.rsplit(":", 1)
    host = h.strip("[]")
    try:
        port = int(p)
    except ValueError:
        port = 11211

try:
    with socket.create_connection((host, port), timeout=5) as s:
        s.settimeout(4)
        s.sendall(b"stats\r\n")
        data = s.recv(4096).decode("utf-8", errors="ignore")
        if "STAT version " in data or "STAT pid " in data:
            lines = [ln for ln in data.splitlines() if ln.startswith("STAT version ") or ln.startswith("STAT curr_items ")]
            print(f"CONFIRMED Memcached unauthenticated access on {host}:{port}: " + " | ".join(lines[:4]))
            sys.exit(0)
        print(f"Memcached did not return stats on {host}:{port}")
        sys.exit(1)
except Exception as e:
    print(f"Memcached probe error on {host}:{port}: {e}")
    sys.exit(1)
