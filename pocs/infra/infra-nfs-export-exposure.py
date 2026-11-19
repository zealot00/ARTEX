# artex-name: infra-nfs-export-exposure
# artex-severity: high
# artex-tags: nfs,rpc,file,unauth,infra,intranet
# artex-desc: Detect exposed NFS exports via showmount or nmap nfs-showmount script.
# artex-guidance: Restrict /etc/exports to specific client IPs and enforce root_squash.
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

if shutil.which("showmount"):
    try:
        r = subprocess.run(["showmount", "-e", host], capture_output=True, text=True, timeout=10)
        lines = [ln.strip() for ln in (r.stdout or "").splitlines() if ln.strip() and not ln.lower().startswith("export list")]
        if r.returncode == 0 and lines:
            print(f"CONFIRMED NFS exports on {host}: " + "; ".join(lines[:10]))
            sys.exit(0)
    except Exception as e:
        print(f"showmount error: {e}")

if shutil.which("nmap"):
    try:
        r = subprocess.run(["nmap", "-Pn", "-p", "111,2049", "--script", "nfs-showmount", host], capture_output=True, text=True, timeout=20)
        out = r.stdout or ""
        if "nfs-showmount:" in out:
            print(f"CONFIRMED NFS exports on {host}:\n" + out[:1000])
            sys.exit(0)
    except Exception as e:
        print(f"nmap error: {e}")

print(f"No exposed NFS exports detected on {host}")
sys.exit(1)
