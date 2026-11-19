# artex-name: infra-ssh-weak-algos-auth
# artex-severity: medium
# artex-tags: ssh,crypto,infra,misconfig,intranet
# artex-desc: Audit SSH service banner, legacy SSHv1, weak ciphers/KEX/MACs (CBC, arcfour, diffie-hellman-group1-sha1), and password authentication status.
# artex-guidance: Record weak SSH algorithms or open password auth under NET-TLS / AUTH-PWD; if password auth is enabled, follow up with bounded run_credential_audit.
import os, shutil, socket, subprocess, sys, urllib.parse

raw = os.environ.get("ARTEX_POC_TARGET", "").strip()
if not raw:
    print("ARTEX_POC_TARGET is required", file=sys.stderr)
    sys.exit(2)

host, port = raw, 22
if "://" in raw:
    u = urllib.parse.urlsplit(raw)
    host = u.hostname or raw
    port = u.port or 22
elif ":" in raw:
    h, p = raw.rsplit(":", 1)
    host = h.strip("[]")
    try:
        port = int(p)
    except ValueError:
        port = 22

findings = []
try:
    with socket.create_connection((host, port), timeout=5) as s:
        s.settimeout(4)
        banner = s.recv(256).decode("utf-8", errors="ignore").strip()
        if banner:
            print(f"banner={banner}")
            if banner.startswith("SSH-1."):
                findings.append(f"SSHV1_ENABLED ({banner})")
except Exception as e:
    print(f"banner probe error: {e}")

weak_markers = [
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "arcfour",
    "3des-cbc",
    "aes128-cbc",
    "aes256-cbc",
    "ssh-dss",
    "hmac-md5",
]
if shutil.which("nmap"):
    try:
        r = subprocess.run(
            ["nmap", "-Pn", "-p", str(port), "--script", "ssh2-enum-algos,ssh-auth-methods", host],
            capture_output=True, text=True, timeout=20,
        )
        out = r.stdout or ""
        low = out.lower()
        hit_algos = [m for m in weak_markers if m in low]
        if hit_algos:
            findings.append("WEAK_SSH_ALGOS: " + ", ".join(hit_algos))
        if "password" in low and "ssh-auth-methods" in low:
            findings.append("SSH_PASSWORD_AUTH_ENABLED")
    except Exception as e:
        print(f"nmap error: {e}")

if findings:
    print(f"CONFIRMED SSH weak config on {host}:{port}:")
    for f in findings:
        print(" - " + f)
    sys.exit(0)
print(f"No weak SSH algorithms or legacy protocol detected on {host}:{port}")
sys.exit(1)
