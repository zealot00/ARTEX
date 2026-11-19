# artex-name: infra-redis-sentinel-config-audit
# artex-severity: high
# artex-tags: redis,sentinel,database,unauth,infra,intranet
# artex-desc: Read-only Redis Sentinel (:26379 SENTINEL masters) and Redis (:6379 CONFIG GET requirepass/dir) weak configuration audit.
# artex-guidance: Configure requirepass / ACLs on both Redis data nodes and Sentinel instances, and rename/disable CONFIG.
import os, socket, sys, urllib.parse

raw = os.environ.get("ARTEX_POC_TARGET", "").strip()
if not raw:
    print("ARTEX_POC_TARGET is required", file=sys.stderr)
    sys.exit(2)

host, port = raw, 26379
if "://" in raw:
    u = urllib.parse.urlsplit(raw)
    host = u.hostname or raw
    port = u.port or 26379
elif ":" in raw:
    h, p = raw.rsplit(":", 1)
    host = h.strip("[]")
    try:
        port = int(p)
    except ValueError:
        port = 26379

try:
    with socket.create_connection((host, port), timeout=5) as s:
        s.settimeout(5)
        cmd = b"SENTINEL masters\r\n" if port == 26379 else b"CONFIG GET requirepass\r\nCONFIG GET dir\r\n"
        s.sendall(cmd)
        data = s.recv(4096).decode("utf-8", errors="ignore")
        if ("name" in data and "ip" in data and "port" in data) or ("requirepass" in data and "-NOAUTH" not in data):
            preview = data.replace("\r\n", " ")[:240]
            print(f"CONFIRMED Redis/Sentinel unauthenticated config/topology exposure on {host}:{port}: {preview}")
            sys.exit(0)
        print(f"Redis/Sentinel protected or non-matching response on {host}:{port}")
        sys.exit(1)
except Exception as e:
    print(f"Redis/Sentinel probe error on {host}:{port}: {e}")
    sys.exit(1)
