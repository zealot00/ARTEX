# artex-name: infra-mysql-empty-root-probe
# artex-severity: critical
# artex-tags: mysql,mariadb,database,unauth,infra,intranet
# artex-desc: Probe MySQL/MariaDB (:3306) server version greeting and test whether 'root' accepts an empty password (read-only SELECT VERSION()).
# artex-guidance: Set a strong root password, disable remote root login, and restrict port 3306 to application subnets.
import os, shutil, socket, subprocess, sys, urllib.parse

raw = os.environ.get("ARTEX_POC_TARGET", "").strip()
if not raw:
    print("ARTEX_POC_TARGET is required", file=sys.stderr)
    sys.exit(2)

host, port = raw, 3306
if "://" in raw:
    u = urllib.parse.urlsplit(raw)
    host = u.hostname or raw
    port = u.port or 3306
elif ":" in raw:
    h, p = raw.rsplit(":", 1)
    host = h.strip("[]")
    try:
        port = int(p)
    except ValueError:
        port = 3306

version = ""
try:
    with socket.create_connection((host, port), timeout=5) as s:
        s.settimeout(4)
        pkt = s.recv(512)
        if len(pkt) > 6 and pkt[4] == 10:
            end = pkt.find(b"\x00", 5)
            if end > 5:
                version = pkt[5:end].decode("utf-8", errors="ignore")
                print(f"mysql_greeting_version={version}")
except Exception as e:
    print(f"MySQL greeting error on {host}:{port}: {e}")
    sys.exit(1)

if shutil.which("mysql"):
    try:
        r = subprocess.run(
            ["mysql", "-h", host, "-P", str(port), "-u", "root", "--connect-timeout=5", "-N", "-e", "SELECT VERSION();"],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode == 0 and (r.stdout or "").strip():
            print(f"CONFIRMED MySQL empty root password on {host}:{port}: version={(r.stdout or '').strip()}")
            sys.exit(0)
    except Exception as e:
        print(f"mysql cli error: {e}")

print(f"MySQL root empty password rejected on {host}:{port} (version={version})")
sys.exit(1)
