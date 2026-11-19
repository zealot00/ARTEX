# artex-name: infra-ldap-anonymous-bind
# artex-severity: medium
# artex-tags: ldap,ad,directory,samba,unauth,infra,intranet
# artex-desc: Check whether LDAP/AD/Samba Directory permits anonymous base/RootDSE bind and exposes namingContexts.
# artex-guidance: Record exposed namingContexts under AD-DIR; check if anonymous subtree search is also permitted.
import os, shutil, subprocess, sys, urllib.parse

raw = os.environ.get("ARTEX_POC_TARGET", "").strip()
if not raw:
    print("ARTEX_POC_TARGET is required", file=sys.stderr)
    sys.exit(2)

if not shutil.which("ldapsearch"):
    print("ldapsearch binary not installed", file=sys.stderr)
    sys.exit(1)

uri = raw if "://" in raw else f"ldap://{raw}"
try:
    r = subprocess.run(["ldapsearch", "-x", "-H", uri, "-s", "base", "namingContexts"], capture_output=True, text=True, timeout=10)
    out = r.stdout or ""
    contexts = [ln.strip() for ln in out.splitlines() if ln.lower().startswith("namingcontexts:")]
    if contexts:
        print(f"CONFIRMED LDAP anonymous bind on {uri}: " + "; ".join(contexts[:5]))
        sys.exit(0)
    print(f"No anonymous LDAP namingContexts exposed on {uri}")
    sys.exit(1)
except Exception as e:
    print(f"ldapsearch error: {e}")
    sys.exit(1)
