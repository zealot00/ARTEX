# artex-name: intranet-cors-arbitrary-origin
# artex-severity: medium
# artex-tags: cors,misconfig,web,intranet
# artex-desc: Check whether the target reflects an arbitrary Origin with Access-Control-Allow-Credentials: true.
# artex-guidance: Only report as a finding when sensitive authenticated endpoints reflect arbitrary Origin + Allow-Credentials: true.
import os, sys, urllib.request

target = os.environ.get("ARTEX_POC_TARGET", "").strip()
if not target:
    print("ARTEX_POC_TARGET is required", file=sys.stderr)
    sys.exit(2)

evil = "https://cors-probe.invalid"
req = urllib.request.Request(target, method="GET", headers={"Origin": evil, "User-Agent": "ARTEX-CORS-Probe/1.0"})
try:
    with urllib.request.urlopen(req, timeout=8) as resp:
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "")
        print(f"status={resp.status} ACAO={acao!r} ACAC={acac!r}")
        if acao == evil and acac.lower() == "true":
            print("CONFIRMED: arbitrary Origin reflected with Allow-Credentials: true")
            sys.exit(0)
        sys.exit(1)
except Exception as e:
    print(f"probe error: {e}")
    sys.exit(1)
