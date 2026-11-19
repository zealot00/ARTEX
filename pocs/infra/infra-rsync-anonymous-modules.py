# artex-name: infra-rsync-anonymous-modules
# artex-severity: high
# artex-tags: rsync,file,unauth,infra,intranet
# artex-desc: Pure-TCP read-only probe listing anonymously exposed rsync daemon (:873) modules.
# artex-guidance: Review exposed module names; enforce auth users / secrets file and hosts allow in rsyncd.conf.
import os, socket, sys, urllib.parse

raw = os.environ.get("ARTEX_POC_TARGET", "").strip()
if not raw:
    print("ARTEX_POC_TARGET is required", file=sys.stderr)
    sys.exit(2)

host, port = raw, 873
if "://" in raw:
    u = urllib.parse.urlsplit(raw)
    host = u.hostname or raw
    port = u.port or 873
elif ":" in raw:
    h, p = raw.rsplit(":", 1)
    host = h.strip("[]")
    try:
        port = int(p)
    except ValueError:
        port = 873

try:
    with socket.create_connection((host, port), timeout=5) as s:
        s.settimeout(4)
        greeting = s.recv(256).decode("utf-8", errors="ignore").strip()
        if not greeting.startswith("@RSYNCD:"):
            print(f"Not an rsync daemon on {host}:{port}")
            sys.exit(1)
        s.sendall((greeting + "\n").encode("utf-8"))
        s.sendall(b"#list\n")
        listing = s.recv(4096).decode("utf-8", errors="ignore")
        modules = [ln.strip() for ln in listing.splitlines() if ln.strip() and not ln.startswith("@RSYNCD:")]
        if modules:
            print(f"CONFIRMED rsync anonymous module listing on {host}:{port}: " + ", ".join(modules[:10]))
            sys.exit(0)
        print(f"Rsync daemon found on {host}:{port} but no anonymous modules listed")
        sys.exit(1)
except Exception as e:
    print(f"rsync probe error on {host}:{port}: {e}")
    sys.exit(1)
