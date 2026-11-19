# artex-name: infra-snmp-default-community
# artex-severity: medium
# artex-tags: snmp,network,misconfig,infra,intranet
# artex-desc: Check whether SNMPv2c accepts the default 'public' community string and discloses sysDescr.
# artex-guidance: Report sysDescr exposure and recommend disabling SNMPv1/v2c or rotating community strings / migrating to SNMPv3.
import os, shutil, subprocess, sys, urllib.parse

raw = os.environ.get("ARTEX_POC_TARGET", "").strip()
if not raw:
    print("ARTEX_POC_TARGET is required", file=sys.stderr)
    sys.exit(2)

if not shutil.which("snmpget"):
    print("snmpget binary not installed", file=sys.stderr)
    sys.exit(1)

host = raw
if "://" in raw:
    host = urllib.parse.urlsplit(raw).hostname or raw
elif ":" in raw:
    host = raw.split(":", 1)[0]

try:
    r = subprocess.run(["snmpget", "-v2c", "-c", "public", "-t", "3", "-r", "1", host, "1.3.6.1.2.1.1.1.0"], capture_output=True, text=True, timeout=10)
    out = (r.stdout or "").strip()
    if r.returncode == 0 and out:
        print(f"CONFIRMED SNMPv2c default community 'public' on {host}: {out[:300]}")
        sys.exit(0)
    print(f"SNMPv2c default community 'public' rejected or unreachable on {host}")
    sys.exit(1)
except Exception as e:
    print(f"snmpget error: {e}")
    sys.exit(1)
