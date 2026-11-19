# artex-name: infra-print-cups-ipp-exposure
# artex-severity: medium
# artex-tags: print,cups,ipp,jetdirect,infra,misconfig,intranet
# artex-desc: Audit exposed print services: CUPS/IPP web interface (:631 /printers, /admin) and raw JetDirect (:9100 PJL INFO ID).
# artex-guidance: Record exposed print interfaces under WIN-SVC; restrict CUPS/IPP and JetDirect 9100 to dedicated printer management VLANs.
import os, socket, ssl, sys, urllib.parse, urllib.request

raw = os.environ.get("ARTEX_POC_TARGET", "").strip()
if not raw:
    print("ARTEX_POC_TARGET is required", file=sys.stderr)
    sys.exit(2)

host = raw
custom_port = None
if "://" in raw:
    u = urllib.parse.urlsplit(raw)
    host = u.hostname or raw
    custom_port = u.port
elif ":" in raw:
    h, p = raw.rsplit(":", 1)
    host = h.strip("[]")
    try:
        custom_port = int(p)
    except ValueError:
        custom_port = None

findings = []
ctx = ssl._create_unverified_context()

cups_ports = [custom_port] if custom_port else [631]
for cp in cups_ports:
    for scheme in ("http", "https"):
        for path in ("/printers/", "/admin", "/"):
            url = f"{scheme}://{host}:{cp}{path}"
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "ARTEX-Print-Audit/1.0"})
                with urllib.request.urlopen(req, timeout=4, context=ctx) as r:
                    body = r.read(4096).decode("utf-8", errors="ignore")
                    srv = r.headers.get("Server", "")
                    if r.status == 200 and ("CUPS" in body or "CUPS" in srv or "Printers" in body):
                        findings.append(f"CUPS_EXPOSED {url} (Server={srv!r})")
                        break
            except Exception:
                continue
        if findings:
            break

if not custom_port or custom_port == 9100:
    try:
        with socket.create_connection((host, 9100), timeout=4) as s:
            s.settimeout(3)
            s.sendall(b"\x1b%-12345X@PJL INFO ID\r\n\x1b%-12345X")
            try:
                data = s.recv(1024).decode("utf-8", errors="ignore").strip()
            except Exception:
                data = ""
            findings.append(f"JETDIRECT_9100_OPEN (pjl={data[:120]!r})")
    except Exception:
        pass

if findings:
    print(f"CONFIRMED print service exposure on {host}:")
    for f in findings:
        print(" - " + f)
    sys.exit(0)
print(f"No CUPS/IPP (:631) or JetDirect (:9100) exposure detected on {host}")
sys.exit(1)
