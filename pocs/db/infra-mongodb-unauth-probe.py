# artex-name: infra-mongodb-unauth-probe
# artex-severity: critical
# artex-tags: mongodb,database,unauth,infra,intranet
# artex-desc: Pure-TCP BSON OP_MSG read-only probe checking whether MongoDB (:27017) permits unauthenticated listDatabases.
# artex-guidance: Report exposed database names as read-only proof; enable security.authorization: enabled in mongod.conf.
import os, socket, struct, sys, urllib.parse

raw = os.environ.get("ARTEX_POC_TARGET", "").strip()
if not raw:
    print("ARTEX_POC_TARGET is required", file=sys.stderr)
    sys.exit(2)

host, port = raw, 27017
if "://" in raw:
    u = urllib.parse.urlsplit(raw)
    host = u.hostname or raw
    port = u.port or 27017
elif ":" in raw:
    h, p = raw.rsplit(":", 1)
    host = h.strip("[]")
    try:
        port = int(p)
    except ValueError:
        port = 27017

# Build minimal BSON doc: { "listDatabases": 1, "$db": "admin" }
def bson_int32(k, v):
    return b"\x10" + k.encode() + b"\x00" + struct.pack("<i", v)

def bson_str(k, v):
    vb = v.encode() + b"\x00"
    return b"\x02" + k.encode() + b"\x00" + struct.pack("<i", len(vb)) + vb

doc_body = bson_int32("listDatabases", 1) + bson_str("$db", "admin") + b"\x00"
doc = struct.pack("<i", len(doc_body) + 4) + doc_body
# OP_MSG (2013): header (16 bytes) + flagBits (4) + kind=0 (1) + doc
payload = struct.pack("<I", 0) + b"\x00" + doc
header = struct.pack("<iiii", 16 + len(payload), 1, 0, 2013)

try:
    with socket.create_connection((host, port), timeout=5) as s:
        s.settimeout(5)
        s.sendall(header + payload)
        resp = s.recv(4096)
        text = resp.decode("latin-1", errors="ignore")
        if "databases" in text and "totalSize" in text and "Unauthorized" not in text:
            print(f"CONFIRMED MongoDB unauthenticated listDatabases on {host}:{port} (resp_bytes={len(resp)})")
            sys.exit(0)
        print(f"MongoDB requires authentication or non-MongoDB response on {host}:{port}")
        sys.exit(1)
except Exception as e:
    print(f"MongoDB probe error on {host}:{port}: {e}")
    sys.exit(1)
