# artex-name: infra-zookeeper-unauth-4lw
# artex-severity: high
# artex-tags: zookeeper,bigdata,unauth,infra,intranet
# artex-desc: Pure-TCP read-only probe checking ZooKeeper (:2181) unauthenticated four-letter words (ruok / stat / envi).
# artex-guidance: Restrict 4lw.commands.whitelist and enforce SASL/firewall isolation on port 2181.
import os, socket, sys, urllib.parse

raw = os.environ.get("ARTEX_POC_TARGET", "").strip()
if not raw:
    print("ARTEX_POC_TARGET is required", file=sys.stderr)
    sys.exit(2)

host, port = raw, 2181
if "://" in raw:
    u = urllib.parse.urlsplit(raw)
    host = u.hostname or raw
    port = u.port or 2181
elif ":" in raw:
    h, p = raw.rsplit(":", 1)
    host = h.strip("[]")
    try:
        port = int(p)
    except ValueError:
        port = 2181

hits = []
for cmd in ("ruok", "stat", "envi"):
    try:
        with socket.create_connection((host, port), timeout=4) as s:
            s.settimeout(4)
            s.sendall(cmd.encode("ascii"))
            data = s.recv(2048).decode("utf-8", errors="ignore").strip()
            if data and ("imok" in data or "Zookeeper version:" in data or "Environment:" in data):
                first_line = data.splitlines()[0][:160]
                hits.append(f"{cmd} -> {first_line}")
    except Exception:
        pass

if hits:
    print(f"CONFIRMED ZooKeeper unauthenticated 4lw on {host}:{port}: " + " | ".join(hits))
    sys.exit(0)
print(f"No unauthenticated ZooKeeper 4lw response on {host}:{port}")
sys.exit(1)
