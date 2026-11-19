# artex-name: infra-tls-weak-protocol-cipher
# artex-severity: medium
# artex-tags: tls,ssl,crypto,mlps,infra,intranet
# artex-desc: Audit TLS endpoint for deprecated SSLv3/TLSv1.0/TLSv1.1 protocols or weak RC4/3DES/EXPORT ciphers using sslscan.
# artex-guidance: Record verified TLS posture under NET-TLS (MLPS 2.0); enforce TLSv1.2+ with AEAD ciphers.
import os, shutil, subprocess, sys, urllib.parse

raw = os.environ.get("ARTEX_POC_TARGET", "").strip()
if not raw:
    print("ARTEX_POC_TARGET is required", file=sys.stderr)
    sys.exit(2)

if not shutil.which("sslscan"):
    print("sslscan binary not installed", file=sys.stderr)
    sys.exit(1)

target = raw
if "://" in raw:
    u = urllib.parse.urlsplit(raw)
    port = u.port or 443
    target = f"{u.hostname}:{port}"

try:
    r = subprocess.run(["sslscan", "--no-colour", target], capture_output=True, text=True, timeout=25)
    out = r.stdout or ""
    issues = []
    for line in out.splitlines():
        s = line.strip()
        if any(p in s for p in ("SSLv2   enabled", "SSLv3   enabled", "TLSv1.0   enabled", "TLSv1.1   enabled")):
            issues.append(s)
        if ("Accepted" in s or "Preferred" in s) and any(w in s.upper() for w in ("RC4", "DES-CBC3", "EXP", "NULL", "MD5")):
            issues.append(s)
    if issues:
        print(f"CONFIRMED weak TLS config on {target}:")
        for i in issues[:12]:
            print(" - " + i)
        sys.exit(0)
    print(f"TLS configuration on {target} shows no SSLv2/v3/TLSv1.0/v1.1 or weak ciphers")
    sys.exit(1)
except Exception as e:
    print(f"sslscan error: {e}")
    sys.exit(1)
