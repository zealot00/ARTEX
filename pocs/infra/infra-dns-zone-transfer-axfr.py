# artex-name: infra-dns-zone-transfer-axfr
# artex-severity: high
# artex-tags: dns,axfr,infra,misconfig,intranet
# artex-desc: Check whether an internal DNS server permits unauthenticated zone transfer (AXFR). Target format: 'dns_server/zone' or 'zone@dns_server'.
# artex-guidance: Restrict allow-transfer in BIND/DNS config to authorized secondary nameservers only.
import os, shutil, subprocess, sys

raw = os.environ.get("ARTEX_POC_TARGET", "").strip()
if not raw:
    print("ARTEX_POC_TARGET is required (use 'zone@dns_ip' or 'dns_ip/zone')", file=sys.stderr)
    sys.exit(2)
if not shutil.which("dig"):
    print("dig binary not installed", file=sys.stderr)
    sys.exit(1)

if "@" in raw:
    zone, server = raw.split("@", 1)
elif "/" in raw:
    server, zone = raw.split("/", 1)
else:
    print("Provide both DNS server and zone name (e.g. 'corp.local@10.10.0.53')", file=sys.stderr)
    sys.exit(2)

try:
    r = subprocess.run(["dig", "+time=4", "+tries=1", f"@{server.strip()}", zone.strip(), "AXFR"], capture_output=True, text=True, timeout=10)
    out = r.stdout or ""
    if "XFR size:" in out and "Transfer failed" not in out:
        lines = [ln for ln in out.splitlines() if ln and not ln.startswith(";")][:15]
        print(f"CONFIRMED DNS AXFR zone transfer on {zone}@{server}:\n" + "\n".join(lines))
        sys.exit(0)
    print(f"DNS AXFR refused or failed for {zone}@{server}")
    sys.exit(1)
except Exception as e:
    print(f"dig error: {e}")
    sys.exit(1)
