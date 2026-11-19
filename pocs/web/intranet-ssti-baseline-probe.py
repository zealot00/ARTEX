# artex-name: intranet-ssti-baseline-probe
# artex-severity: high
# artex-tags: ssti,template,injection,intranet
# artex-desc: Probe query parameters on the target URL with benign template expressions ({{7*7}}, ${7*7}) and check for evaluated output (49).
# artex-guidance: If 49 appears only when the expression is injected (and not in baseline), identify the template engine and verify bounded impact.
import os, sys, urllib.parse, urllib.request

target = os.environ.get("ARTEX_POC_TARGET", "").strip()
if not target:
    print("ARTEX_POC_TARGET is required", file=sys.stderr)
    sys.exit(2)

u = urllib.parse.urlsplit(target)
qs = urllib.parse.parse_qs(u.query, keep_blank_values=True)
if not qs:
    qs = {"q": [""], "name": [""], "template": [""]}

def get_body(url):
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "ARTEX-SSTI-Probe/1.0"}), timeout=6) as r:
            return r.read(8192).decode("utf-8", errors="ignore")
    except Exception:
        return ""

baseline = get_body(target)
if "918273" in baseline:
    sys.exit(1)

exprs = ["{{918*1000+273}}", "${918*1000+273}", "#{918*1000+273}"]
for param in list(qs.keys())[:5]:
    for expr in exprs:
        mut = {k: v[:] for k, v in qs.items()}
        mut[param] = [expr]
        test_url = urllib.parse.urlunsplit((u.scheme, u.netloc, u.path, urllib.parse.urlencode(mut, doseq=True), ""))
        body = get_body(test_url)
        if "918273" in body and expr not in body:
            print(f"CONFIRMED SSTI candidate on param={param} expr={expr}")
            sys.exit(0)
print("no evaluated SSTI marker observed")
sys.exit(1)
