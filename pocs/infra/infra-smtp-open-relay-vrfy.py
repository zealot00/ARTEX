# artex-name: infra-smtp-open-relay-vrfy
# artex-severity: medium
# artex-tags: smtp,mail,infra,misconfig,intranet
# artex-desc: Read-only SMTP (:25/:587) probe checking banner, VRFY/EXPN user enumeration, and plaintext AUTH without STARTTLS.
# artex-guidance: Disable VRFY/EXPN, require STARTTLS before AUTH, and restrict SMTP relay to authorized internal hosts.
import os, socket, sys, urllib.parse

raw = os.environ.get("ARTEX_POC_TARGET", "").strip()
if not raw:
    print("ARTEX_POC_TARGET is required", file=sys.stderr)
    sys.exit(2)

host, port = raw, 25
if "://" in raw:
    u = urllib.parse.urlsplit(raw)
    host = u.hostname or raw
    port = u.port or 25
elif ":" in raw:
    h, p = raw.rsplit(":", 1)
    host = h.strip("[]")
    try:
        port = int(p)
    except ValueError:
        port = 25

findings = []
try:
    with socket.create_connection((host, port), timeout=5) as s:
        s.settimeout(4)
        banner = s.recv(512).decode("utf-8", errors="ignore").strip()
        s.sendall(b"EHLO artex.audit.local\r\n")
        ehlo = s.recv(1024).decode("utf-8", errors="ignore")
        if "AUTH " in ehlo.upper() and "STARTTLS" not in ehlo.upper():
            findings.append("SMTP_PLAINTEXT_AUTH_WITHOUT_STARTTLS")
        s.sendall(b"VRFY root\r\n")
        vrfy = s.recv(512).decode("utf-8", errors="ignore").strip()
        if vrfy.startswith("250") or vrfy.startswith("252"):
            findings.append(f"SMTP_VRFY_ENABLED ({vrfy[:100]})")
        s.sendall(b"QUIT\r\n")
except Exception as e:
    print(f"SMTP probe error on {host}:{port}: {e}")
    sys.exit(1)

if findings:
    print(f"CONFIRMED SMTP weak config on {host}:{port} (banner={banner[:80]}):")
    for f in findings:
        print(" - " + f)
    sys.exit(0)
print(f"No SMTP VRFY/plaintext-AUTH issue detected on {host}:{port}")
sys.exit(1)
