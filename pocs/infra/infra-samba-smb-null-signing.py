# artex-name: infra-samba-smb-null-signing
# artex-severity: high
# artex-tags: samba,smb,windows,infra,misconfig,intranet
# artex-desc: Audit Samba/SMB host for anonymous null-session share listing, disabled SMB signing (relay risk), and legacy SMBv1 dialect.
# artex-guidance: Record exposed anonymous shares, SMB signing status, or SMBv1 dialect under WIN-SVC; if authorized and lateral_gate is approved, inspect readable non-sensitive config shares.
import os, shutil, subprocess, sys, urllib.parse

raw = os.environ.get("ARTEX_POC_TARGET", "").strip()
if not raw:
    print("ARTEX_POC_TARGET is required", file=sys.stderr)
    sys.exit(2)

host = raw
if "://" in raw:
    host = urllib.parse.urlsplit(raw).hostname or raw
elif ":" in raw:
    host = raw.split(":", 1)[0]

findings = []

if shutil.which("smbclient"):
    try:
        r = subprocess.run(["smbclient", "-L", f"//{host}", "-N", "-g"], capture_output=True, text=True, timeout=10)
        out = (r.stdout or "") + "\n" + (r.stderr or "")
        shares = [line.strip() for line in out.splitlines() if line.startswith("Disk|") or line.startswith("IPC|")]
        if shares:
            findings.append("SMB_NULL_SESSION_SHARES: " + ", ".join(shares[:10]))
    except Exception as e:
        print(f"smbclient error: {e}")

if shutil.which("nmap"):
    try:
        r = subprocess.run(
            ["nmap", "-Pn", "-p", "445", "--script", "smb2-security-mode,smb-protocols", host],
            capture_output=True, text=True, timeout=20,
        )
        out = r.stdout or ""
        if "Message signing enabled but not required" in out or "Message signing disabled" in out:
            findings.append("SMB_SIGNING_NOT_REQUIRED")
        if "NT LM 0.12" in out or "SMBv1" in out:
            findings.append("SMBV1_ENABLED")
    except Exception as e:
        print(f"nmap error: {e}")

if findings:
    print("CONFIRMED SMB/Samba weak configuration on " + host + ":")
    for f in findings:
        print(" - " + f)
    sys.exit(0)

print(f"No anonymous SMB shares, disabled signing, or SMBv1 detected on {host}")
sys.exit(1)
