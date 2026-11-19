# artex-name: infra-ftp-anonymous-login
# artex-severity: high
# artex-tags: ftp,unauth,infra,misconfig,intranet
# artex-desc: Check whether FTP server permits anonymous login and exposes directory listings.
# artex-guidance: Disable anonymous FTP login or restrict to non-sensitive read-only public mirrors.
import ftplib, os, sys, urllib.parse

raw = os.environ.get("ARTEX_POC_TARGET", "").strip()
if not raw:
    print("ARTEX_POC_TARGET is required", file=sys.stderr)
    sys.exit(2)

host, port = raw, 21
if "://" in raw:
    u = urllib.parse.urlsplit(raw)
    host = u.hostname or raw
    port = u.port or 21
elif ":" in raw:
    h, p = raw.rsplit(":", 1)
    host = h.strip("[]")
    try:
        port = int(p)
    except ValueError:
        port = 21

try:
    ftp = ftplib.FTP()
    ftp.connect(host, port, timeout=5)
    welcome = ftp.getwelcome()
    ftp.login("anonymous", "anonymous@audit.local")
    entries = []
    try:
        entries = ftp.nlst()[:10]
    except Exception:
        pass
    ftp.quit()
    print(f"CONFIRMED FTP anonymous login on {host}:{port} | welcome={welcome[:120]} | entries={entries}")
    sys.exit(0)
except Exception as e:
    print(f"FTP anonymous login rejected or unreachable on {host}:{port}: {e}")
    sys.exit(1)
