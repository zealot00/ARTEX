package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

func nucleiTemplatesDir() string {
	for _, k := range []string{"ARTEX_NUCLEI_TEMPLATES_DIR", "NUCLEI_TEMPLATES_DIR"} {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	candidates := []string{"/opt/nuclei-templates", "./data/nuclei-templates"}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		candidates = append(candidates, filepath.Join(home, "nuclei-templates"))
	}
	for _, dir := range candidates {
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			return dir
		}
	}
	return "/opt/nuclei-templates"
}

// GET /api/pocs — admin JWT only.
func (s *Server) listPocs(w http.ResponseWriter, r *http.Request) {
	if s.m == nil || s.m.pg == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	q := r.URL.Query().Get("query")
	kind := r.URL.Query().Get("kind")
	tag := r.URL.Query().Get("tag")
	items, err := s.m.pg.SearchPocs(q, kind, tag, 100)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if items == nil {
		items = []db.PocRecord{}
	}
	writeJSON(w, 200, map[string]any{"pocs": items})
}

// POST /api/pocs — admin JWT only.
func (s *Server) createPoc(w http.ResponseWriter, r *http.Request) {
	if s.m == nil || s.m.pg == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	var req db.UpsertPocInput
	if err := decode(w, r, &req); err != nil {
		writeErr(w, 400, "invalid JSON")
		return
	}
	req.CreatedBy = "admin"
	rec, created, err := s.m.pg.UpsertPoc(req)
	if err != nil {
		if errors.Is(err, db.ErrPocInvalidName) ||
			errors.Is(err, db.ErrPocInvalidKind) ||
			errors.Is(err, db.ErrPocInvalidSeverity) ||
			errors.Is(err, db.ErrPocEmptyContent) {
			writeErr(w, 400, err.Error())
			return
		}
		writeErr(w, 500, err.Error())
		return
	}
	code := 200
	if created {
		code = 201
	}
	writeJSON(w, code, map[string]any{"poc": rec, "created": created})
}

// DELETE /api/pocs/{id} — admin JWT only.
func (s *Server) deletePoc(w http.ResponseWriter, r *http.Request) {
	if s.m == nil || s.m.pg == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "invalid poc id")
		return
	}
	deleted, err := s.m.pg.DeletePoc(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if !deleted {
		writeErr(w, 404, "poc not found")
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": true, "id": id})
}

func (s *Server) pocTools() []actool.CoreTool {
	return []actool.CoreTool{
		s.toolSearchPocs(),
		s.toolRunPoc(),
		s.toolSavePoc(),
	}
}

func (s *Server) seedPocTools() {
	if s.m == nil || s.m.pg == nil {
		return
	}
	agents, _ := json.Marshal([]string{"worker", "planner", "main", "auto", "pentest"})
	for _, t := range s.pocTools() {
		schema, _ := json.Marshal(t.InputSchema())
		if err := s.m.pg.SeedTool(t.Name(), t.Description(), schema, agents); err != nil {
			log.Printf("[pocs] seed tool %s: %v", t.Name(), err)
		}
	}
	s.seedDefaultPocs()
}

func (s *Server) seedDefaultPocs() {
	if s.m == nil || s.m.pg == nil {
		return
	}
	for _, d := range defaultIntranetPocs() {
		if _, err := s.m.pg.GetPocByRef(d.Name); err == nil {
			continue
		}
		if _, _, err := s.m.pg.UpsertPoc(d); err != nil {
			log.Printf("[pocs] seed default %s: %v", d.Name, err)
		}
	}
}

func defaultIntranetPocs() []db.UpsertPocInput {
	return []db.UpsertPocInput{
		{
			Name:            "intranet-spring-actuator-exposure",
			Kind:            db.PocKindNucleiYAML,
			Severity:        "high",
			Tags:            "spring,actuator,exposure,intranet",
			Description:     "Detect exposed Spring Boot Actuator endpoints (/actuator/env, /actuator/heapdump, /actuator/mappings).",
			ExploitGuidance: "Inspect /actuator/env or /actuator/configprops for leaked DB/Redis/JWT secrets (never dump full heapdump unnecessarily) and store credentials in task_credentials.",
			CreatedBy:       "system",
			Content: `id: intranet-spring-actuator-exposure
info:
  name: Spring Boot Actuator Exposure
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/actuator"
      - "{{BaseURL}}/actuator/env"
      - "{{BaseURL}}/actuator/mappings"
      - "{{BaseURL}}/env"
    stop-at-first-match: true
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words:
          - '"_links"'
          - '"propertySources"'
          - '"dispatcherServlets"'
        condition: or
`,
		},
		{
			Name:            "intranet-swagger-openapi-exposure",
			Kind:            db.PocKindNucleiYAML,
			Severity:        "medium",
			Tags:            "swagger,openapi,api,exposure,intranet",
			Description:     "Detect unauthenticated Swagger / OpenAPI specification endpoints for API surface discovery.",
			ExploitGuidance: "Parse discovered paths and parameters from the OpenAPI JSON, then test unauthenticated access, IDOR, and mass assignment against sensitive endpoints.",
			CreatedBy:       "system",
			Content: `id: intranet-swagger-openapi-exposure
info:
  name: Swagger / OpenAPI Specification Exposure
  severity: medium
http:
  - method: GET
    path:
      - "{{BaseURL}}/v2/api-docs"
      - "{{BaseURL}}/v3/api-docs"
      - "{{BaseURL}}/swagger-ui.html"
      - "{{BaseURL}}/swagger-ui/index.html"
    stop-at-first-match: true
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words:
          - '"swagger"'
          - '"openapi"'
          - 'Swagger UI'
        condition: or
`,
		},
		{
			Name:            "intranet-dotenv-git-exposure",
			Kind:            db.PocKindNucleiYAML,
			Severity:        "high",
			Tags:            "env,git,config,leak,intranet",
			Description:     "Detect exposed .env or .git/config files leaking database credentials, API keys, or source repo metadata.",
			ExploitGuidance: "Extract non-destructive credential proof from .env or .git/config and record valid secrets in task_credentials for downstream verification.",
			CreatedBy:       "system",
			Content: `id: intranet-dotenv-git-exposure
info:
  name: Exposed .env or .git/config
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/.env"
      - "{{BaseURL}}/.git/config"
    stop-at-first-match: true
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words:
          - "DB_PASSWORD"
          - "APP_KEY"
          - "[remote \"origin\"]"
        condition: or
`,
		},
		{
			Name:            "intranet-blind-ssrf-oob-probe",
			Kind:            db.PocKindPythonScript,
			Severity:        "high",
			Tags:            "ssrf,oob,blind,intranet",
			Description:     "Probe common URL/webhook/callback query parameters with the task's ARTEX_OOB_URL callback.",
			ExploitGuidance: "Confirm hit via oob_poll_hits; if confirmed, test bounded internal service reachability (within fence) to demonstrate SSRF impact.",
			CreatedBy:       "system",
			Content: `import os, sys, urllib.parse, urllib.request

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
`,
		},
		{
			Name:            "intranet-graphql-introspection",
			Kind:            db.PocKindNucleiYAML,
			Severity:        "low",
			Tags:            "graphql,introspection,api,intranet",
			Description:     "Detect GraphQL endpoints with introspection enabled to map internal schemas, queries, and mutations.",
			ExploitGuidance: "Enumerate returned Query/Mutation types and test sensitive mutations/queries for IDOR and broken authorization.",
			CreatedBy:       "system",
			Content: `id: intranet-graphql-introspection
info:
  name: GraphQL Introspection Enabled
  severity: low
http:
  - method: POST
    path:
      - "{{BaseURL}}/graphql"
      - "{{BaseURL}}/api/graphql"
    headers:
      Content-Type: application/json
    body: '{"query":"{__schema{types{name}}}"}'
    stop-at-first-match: true
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words:
          - '"__schema"'
          - '"types"'
        condition: and
`,
		},
		{
			Name:            "intranet-nacos-unauth-probe",
			Kind:            db.PocKindNucleiYAML,
			Severity:        "high",
			Tags:            "nacos,alibaba,middleware,unauth,intranet",
			Description:     "Detect exposed Alibaba Nacos APIs (/nacos/v1/cs/configs, /nacos/v1/auth/users) accessible without authentication.",
			ExploitGuidance: "Check if namespace/config read or user list endpoints return DB/Redis/service credentials without a valid accessToken.",
			CreatedBy:       "system",
			Content: `id: intranet-nacos-unauth-probe
info:
  name: Alibaba Nacos Unauthenticated API Probe
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/nacos/v1/console/health/readiness"
      - "{{BaseURL}}/nacos/v1/ns/instance/list?serviceName=test"
      - "{{BaseURL}}/nacos/v1/auth/users?pageNo=1&pageSize=10"
    stop-at-first-match: true
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words:
          - '"pageItems"'
          - '"hosts"'
          - 'UP'
        condition: or
`,
		},
		{
			Name:            "intranet-druid-monitor-exposure",
			Kind:            db.PocKindNucleiYAML,
			Severity:        "medium",
			Tags:            "druid,java,monitor,unauth,intranet",
			Description:     "Detect unauthenticated Alibaba Druid SQL/Session monitor console.",
			ExploitGuidance: "Inspect exposed SQL queries, datasource URIs, and active session IDs from /druid/websession.json or /druid/sql.json.",
			CreatedBy:       "system",
			Content: `id: intranet-druid-monitor-exposure
info:
  name: Alibaba Druid Monitor Unauthenticated Exposure
  severity: medium
http:
  - method: GET
    path:
      - "{{BaseURL}}/druid/index.html"
      - "{{BaseURL}}/druid/sql.html"
      - "{{BaseURL}}/druid/basic.json"
    stop-at-first-match: true
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words:
          - "Druid Stat Index"
          - '"ResultCode"'
        condition: or
`,
		},
		{
			Name:            "intranet-metrics-prometheus-exposure",
			Kind:            db.PocKindNucleiYAML,
			Severity:        "medium",
			Tags:            "prometheus,metrics,grafana,exposure,intranet",
			Description:     "Detect unauthenticated /metrics, Prometheus, or Grafana datasource/health endpoints.",
			ExploitGuidance: "Review exposed /metrics or /api/datasources for internal service topology, versions, and potential backend targets.",
			CreatedBy:       "system",
			Content: `id: intranet-metrics-prometheus-exposure
info:
  name: Prometheus / Metrics / Grafana Exposure
  severity: medium
http:
  - method: GET
    path:
      - "{{BaseURL}}/metrics"
      - "{{BaseURL}}/actuator/prometheus"
      - "{{BaseURL}}/api/datasources"
    stop-at-first-match: true
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words:
          - "# HELP "
          - "# TYPE "
          - '"typeName"'
        condition: or
`,
		},
		{
			Name:            "intranet-container-api-unauth",
			Kind:            db.PocKindNucleiYAML,
			Severity:        "critical",
			Tags:            "docker,kubernetes,k8s,container,unauth,intranet",
			Description:     "Detect unauthenticated Docker Remote API (/version, /containers/json) or Kubernetes API (/api/v1/namespaces).",
			ExploitGuidance: "Verify read-only cluster/container listing scope first; escalate via kubectl or skills/cloud-k8s-audit within authorized scope.",
			CreatedBy:       "system",
			Content: `id: intranet-container-api-unauth
info:
  name: Docker / Kubernetes Unauthenticated API Exposure
  severity: critical
http:
  - method: GET
    path:
      - "{{BaseURL}}/version"
      - "{{BaseURL}}/containers/json"
      - "{{BaseURL}}/api/v1/namespaces"
    stop-at-first-match: true
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words:
          - '"ApiVersion"'
          - '"Namespace"'
          - '"ImageID"'
        condition: or
`,
		},
		{
			Name:            "intranet-cors-arbitrary-origin",
			Kind:            db.PocKindPythonScript,
			Severity:        "medium",
			Tags:            "cors,misconfig,web,intranet",
			Description:     "Check whether the target reflects an arbitrary Origin with Access-Control-Allow-Credentials: true.",
			ExploitGuidance: "Only report as a finding when sensitive authenticated endpoints reflect arbitrary Origin + Allow-Credentials: true.",
			CreatedBy:       "system",
			Content: `import os, sys, urllib.request

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
`,
		},
		{
			Name:            "intranet-auth-path-header-bypass",
			Kind:            db.PocKindPythonScript,
			Severity:        "high",
			Tags:            "auth-bypass,idor,acl,nginx,spring,intranet",
			Description:     "Probe common HTTP path normalization (..;/, %2e, trailing slash) and proxy header spoofing (X-Forwarded-For, X-Original-URL) against a protected URL.",
			ExploitGuidance: "Compare baseline 401/403 status/length against bypass variants; confirm actual business data is returned before reporting.",
			CreatedBy:       "system",
			Content: `import os, sys, urllib.parse, urllib.request, urllib.error

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
`,
		},
		{
			Name:            "intranet-ssti-baseline-probe",
			Kind:            db.PocKindPythonScript,
			Severity:        "high",
			Tags:            "ssti,template,injection,intranet",
			Description:     "Probe query parameters on the target URL with benign template expressions ({{7*7}}, ${7*7}) and check for evaluated output (49).",
			ExploitGuidance: "If 49 appears only when the expression is injected (and not in baseline), identify the template engine and verify bounded impact.",
			CreatedBy:       "system",
			Content: `import os, sys, urllib.parse, urllib.request

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
`,
		},
		{
			Name:            "infra-samba-smb-null-signing",
			Kind:            db.PocKindPythonScript,
			Severity:        "high",
			Tags:            "samba,smb,windows,infra,misconfig,intranet",
			Description:     "Audit Samba/SMB host for anonymous null-session share listing, disabled SMB signing (relay risk), and legacy SMBv1 dialect.",
			ExploitGuidance: "Record exposed anonymous shares, SMB signing status, or SMBv1 dialect under WIN-SVC; if authorized and lateral_gate is approved, inspect readable non-sensitive config shares.",
			CreatedBy:       "system",
			Content: `import os, shutil, subprocess, sys, urllib.parse

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
`,
		},
		{
			Name:            "infra-k8s-kubelet-unauth",
			Kind:            db.PocKindNucleiYAML,
			Severity:        "critical",
			Tags:            "kubernetes,k8s,kubelet,container,unauth,infra",
			Description:     "Detect unauthenticated Kubelet read-only (:10255) or API (:10250) endpoints exposing Pod specs, env vars, and running containers.",
			ExploitGuidance: "Verify exposed PodList/container metadata (read-only); check if anonymous-auth is enabled on :10250 and record under SYS-CONFIG / AUTH-ACCESS.",
			CreatedBy:       "system",
			Content: `id: infra-k8s-kubelet-unauth
info:
  name: Kubernetes Kubelet Unauthenticated Exposure
  severity: critical
http:
  - method: GET
    path:
      - "{{BaseURL}}/pods"
      - "{{BaseURL}}/runningpods/"
      - "{{BaseURL}}/stats/summary"
    stop-at-first-match: true
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words:
          - '"kind":"PodList"'
          - '"kind": "PodList"'
          - '"nodeName"'
        condition: or
`,
		},
		{
			Name:            "infra-k8s-etcd-unauth",
			Kind:            db.PocKindNucleiYAML,
			Severity:        "critical",
			Tags:            "kubernetes,k8s,etcd,unauth,infra",
			Description:     "Detect unauthenticated etcd (:2379) API exposure allowing cluster metadata or secret key enumeration.",
			ExploitGuidance: "Verify /version or /v2/members read-only exposure; never dump or modify cluster secrets without explicit approval.",
			CreatedBy:       "system",
			Content: `id: infra-k8s-etcd-unauth
info:
  name: Kubernetes etcd Unauthenticated API Exposure
  severity: critical
http:
  - method: GET
    path:
      - "{{BaseURL}}/version"
      - "{{BaseURL}}/v2/keys"
      - "{{BaseURL}}/v2/members"
    stop-at-first-match: true
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words:
          - '"etcdserver"'
          - '"etcdcluster"'
          - '"members"'
        condition: or
`,
		},
		{
			Name:            "infra-k8s-dashboard-unauth",
			Kind:            db.PocKindNucleiYAML,
			Severity:        "high",
			Tags:            "kubernetes,k8s,dashboard,unauth,infra",
			Description:     "Detect unauthenticated Kubernetes Dashboard API access (e.g. skip-login or default ServiceAccount exposure).",
			ExploitGuidance: "Verify whether /api/v1/namespace returns cluster namespaces without a Bearer token.",
			CreatedBy:       "system",
			Content: `id: infra-k8s-dashboard-unauth
info:
  name: Kubernetes Dashboard Unauthenticated Exposure
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/api/v1/namespace"
      - "{{BaseURL}}/api/v1/pod/default"
    stop-at-first-match: true
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words:
          - '"namespaces"'
          - '"pods"'
          - '"listMeta"'
        condition: and
`,
		},
		{
			Name:            "infra-docker-registry-harbor-unauth",
			Kind:            db.PocKindNucleiYAML,
			Severity:        "high",
			Tags:            "docker,harbor,registry,container,unauth,infra",
			Description:     "Detect unauthenticated Docker Registry v2 (/v2/_catalog) or Harbor (/api/v2.0/projects) image repository listing.",
			ExploitGuidance: "List exposed repository names to prove internal image/source disclosure risk.",
			CreatedBy:       "system",
			Content: `id: infra-docker-registry-harbor-unauth
info:
  name: Docker Registry / Harbor Unauthenticated Catalog Exposure
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/v2/_catalog"
      - "{{BaseURL}}/api/v2.0/projects"
    stop-at-first-match: true
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words:
          - '"repositories"'
          - '"project_id"'
        condition: or
`,
		},
		{
			Name:            "infra-redis-unauth-probe",
			Kind:            db.PocKindPythonScript,
			Severity:        "critical",
			Tags:            "redis,database,unauth,infra,intranet",
			Description:     "Pure-TCP read-only probe checking whether Redis accepts unauthenticated PING / INFO server commands.",
			ExploitGuidance: "Report exact redis_version and OS line from INFO server; never run CONFIG SET / FLUSHALL / SAVE in production.",
			CreatedBy:       "system",
			Content: `import os, socket, sys, urllib.parse

raw = os.environ.get("ARTEX_POC_TARGET", "").strip()
if not raw:
    print("ARTEX_POC_TARGET is required", file=sys.stderr)
    sys.exit(2)

host, port = raw, 6379
if "://" in raw:
    u = urllib.parse.urlsplit(raw)
    host = u.hostname or raw
    port = u.port or 6379
elif ":" in raw:
    h, p = raw.rsplit(":", 1)
    host = h.strip("[]")
    try:
        port = int(p)
    except ValueError:
        port = 6379

try:
    with socket.create_connection((host, port), timeout=5) as s:
        s.settimeout(5)
        s.sendall(b"PING\r\nINFO server\r\n")
        data = s.recv(4096).decode("utf-8", errors="ignore")
        if "+PONG" in data or "redis_version:" in data:
            lines = [ln for ln in data.splitlines() if ln.startswith("+PONG") or ln.startswith("redis_version:") or ln.startswith("os:")]
            print(f"CONFIRMED Redis unauthenticated access on {host}:{port}: " + " | ".join(lines[:4]))
            sys.exit(0)
        print(f"Redis authentication required or non-Redis response on {host}:{port}")
        sys.exit(1)
except Exception as e:
    print(f"Redis probe error on {host}:{port}: {e}")
    sys.exit(1)
`,
		},
		{
			Name:            "infra-elasticsearch-unauth",
			Kind:            db.PocKindNucleiYAML,
			Severity:        "high",
			Tags:            "elasticsearch,database,unauth,infra,intranet",
			Description:     "Detect unauthenticated Elasticsearch cluster endpoints (/_cat/indices, /_cluster/health).",
			ExploitGuidance: "List index names and document counts via /_cat/indices?v as read-only proof of data exposure.",
			CreatedBy:       "system",
			Content: `id: infra-elasticsearch-unauth
info:
  name: Elasticsearch Unauthenticated Access
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/_cat/indices?v"
      - "{{BaseURL}}/_cluster/health"
    stop-at-first-match: true
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words:
          - '"cluster_name"'
          - 'docs.count'
        condition: or
`,
		},
		{
			Name:            "infra-jenkins-unauth-exposure",
			Kind:            db.PocKindNucleiYAML,
			Severity:        "high",
			Tags:            "jenkins,ci,cd,unauth,infra,intranet",
			Description:     "Detect unauthenticated Jenkins API (/api/json) or Groovy script console (/script) exposure.",
			ExploitGuidance: "Verify read-only job/version listing on /api/json or anonymous access to /script without executing destructive commands.",
			CreatedBy:       "system",
			Content: `id: infra-jenkins-unauth-exposure
info:
  name: Jenkins Unauthenticated API or Script Console Exposure
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/api/json"
      - "{{BaseURL}}/script"
    stop-at-first-match: true
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words:
          - '"hudson.model.Hudson"'
          - 'Script Console'
        condition: or
`,
		},
		{
			Name:            "infra-ldap-anonymous-bind",
			Kind:            db.PocKindPythonScript,
			Severity:        "medium",
			Tags:            "ldap,ad,directory,samba,unauth,infra,intranet",
			Description:     "Check whether LDAP/AD/Samba Directory permits anonymous base/RootDSE bind and exposes namingContexts.",
			ExploitGuidance: "Record exposed namingContexts under AD-DIR; check if anonymous subtree search is also permitted.",
			CreatedBy:       "system",
			Content: `import os, shutil, subprocess, sys, urllib.parse

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
`,
		},
		{
			Name:            "infra-snmp-default-community",
			Kind:            db.PocKindPythonScript,
			Severity:        "medium",
			Tags:            "snmp,network,misconfig,infra,intranet",
			Description:     "Check whether SNMPv2c accepts the default 'public' community string and discloses sysDescr.",
			ExploitGuidance: "Report sysDescr exposure and recommend disabling SNMPv1/v2c or rotating community strings / migrating to SNMPv3.",
			CreatedBy:       "system",
			Content: `import os, shutil, subprocess, sys, urllib.parse

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
`,
		},
	}
}

func searchOfflineNucleiTemplates(root, query, tag string, limit int) []string {
	if limit <= 0 {
		limit = 30
	}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return nil
	}
	q := strings.ToLower(strings.TrimSpace(query))
	tg := strings.ToLower(strings.TrimSpace(tag))
	var matches []string
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(d.Name()), ".yaml") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return nil
		}
		relSlash := filepath.ToSlash(rel)
		low := strings.ToLower(relSlash)
		if q != "" && !strings.Contains(low, q) {
			return nil
		}
		if tg != "" && !strings.Contains(low, tg) {
			return nil
		}
		matches = append(matches, relSlash)
		if len(matches) >= limit {
			return fs.SkipAll
		}
		return nil
	})
	return matches
}

func resolveOfflineTemplate(root, relPath string) (string, error) {
	cleaned := filepath.Clean(strings.TrimSpace(relPath))
	if cleaned == "." || cleaned == "" || filepath.IsAbs(cleaned) || strings.HasPrefix(cleaned, "..") {
		return "", fmt.Errorf("invalid offline template_path %q", relPath)
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	full := filepath.Join(rootAbs, cleaned)
	rel, err := filepath.Rel(rootAbs, full)
	if err != nil || strings.HasPrefix(rel, "..") {
		return "", fmt.Errorf("template_path escapes offline templates root")
	}
	info, err := os.Stat(full)
	if err != nil || info.IsDir() {
		return "", fmt.Errorf("offline template not found: %s", relPath)
	}
	return full, nil
}

func (s *Server) toolSearchPocs() actool.CoreTool {
	return roTool(
		"search_pocs",
		"Search both the enterprise private PoC repository and offline nuclei-templates (/opt/nuclei-templates) by keyword, CVE, kind, or tag. Use results with run_poc for verification and chained secondary exploitation.",
		objSchema(map[string]any{
			"query": strParam("Keyword, product/tech name, or CVE (e.g. 'weaver', 'shiro', 'CVE-2024')"),
			"kind":  strParam("Optional filter for private PoCs: nuclei_yaml or python_script"),
			"tag":   strParam("Optional tag filter (e.g. 'rce', 'oa', 'sqli')"),
		}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var p struct {
				Query string `json:"query"`
				Kind  string `json:"kind"`
				Tag   string `json:"tag"`
			}
			if len(in) > 0 {
				if err := json.Unmarshal(in, &p); err != nil {
					return actool.Errorf(err.Error()), nil
				}
			}
			var privatePocs []db.PocRecord
			if s.m != nil && s.m.pg != nil {
				items, err := s.m.pg.SearchPocs(p.Query, p.Kind, p.Tag, 30)
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				privatePocs = items
			}
			if privatePocs == nil {
				privatePocs = []db.PocRecord{}
			}
			offline := searchOfflineNucleiTemplates(nucleiTemplatesDir(), p.Query, p.Tag, 30)
			if offline == nil {
				offline = []string{}
			}
			return jsonResult(map[string]any{
				"private_pocs":               privatePocs,
				"offline_nuclei_templates":   offline,
				"offline_templates_root_dir": nucleiTemplatesDir(),
			})
		},
	)
}

func (s *Server) toolRunPoc() actool.CoreTool {
	return wrTool(
		"run_poc",
		"Execute a private enterprise PoC (poc_ref), an offline nuclei template (template_path), or a custom agent-authored inline PoC (inline_kind + inline_content) against an authorized target. Enforces electronic fence and prod_safe_mode, injects optional OOB callback token/URL, and returns exploit_guidance for secondary exploitation.",
		objSchema(map[string]any{
			"task_id":         strParam("Task ID (numeric string)"),
			"target":          strParam("Authorized target URL or host:port (e.g. 'http://10.10.1.5:8080')"),
			"poc_ref":         strParam("Enterprise private PoC numeric ID or exact name (mutually exclusive with template_path / inline_content)"),
			"template_path":   strParam("Relative path inside offline nuclei-templates (mutually exclusive with poc_ref / inline_content)"),
			"inline_kind":     strParam("When authoring a custom PoC on the fly: nuclei_yaml or python_script"),
			"inline_content":  strParam("Custom PoC YAML or Python script content to execute under fence and OOB injection"),
			"oob_token":       strParam("Optional OOB token from oob_create_token to pass ARTEX_OOB_URL/ARTEX_OOB_TOKEN"),
			"timeout_seconds": map[string]any{"type": "integer", "description": "Execution timeout in seconds (default 45, max 120)"},
		}, "task_id", "target"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var p struct {
				TaskID         string `json:"task_id"`
				Target         string `json:"target"`
				PocRef         string `json:"poc_ref"`
				TemplatePath   string `json:"template_path"`
				InlineKind     string `json:"inline_kind"`
				InlineContent  string `json:"inline_content"`
				OOBToken       string `json:"oob_token"`
				TimeoutSeconds int    `json:"timeout_seconds"`
			}
			if err := json.Unmarshal(in, &p); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			p.Target = strings.TrimSpace(p.Target)
			p.PocRef = strings.TrimSpace(p.PocRef)
			p.TemplatePath = strings.TrimSpace(p.TemplatePath)
			p.InlineKind = strings.ToLower(strings.TrimSpace(p.InlineKind))
			p.OOBToken = strings.TrimSpace(p.OOBToken)

			if p.Target == "" {
				return actool.Errorf("target is required"), nil
			}
			hasInline := strings.TrimSpace(p.InlineContent) != ""
			modeCount := 0
			if p.PocRef != "" {
				modeCount++
			}
			if p.TemplatePath != "" {
				modeCount++
			}
			if hasInline {
				modeCount++
			}
			if modeCount != 1 {
				return actool.Errorf("provide exactly one of poc_ref, template_path, or inline_content"), nil
			}

			t := s.m.ResolveTask(strings.TrimSpace(p.TaskID))
			if t == nil {
				return actool.Errorf("task not found"), nil
			}
			if t.Guard != nil {
				probeInput, _ := json.Marshal(map[string]string{
					"command": fmt.Sprintf("nuclei -u %s", p.Target),
				})
				if blocked, reason := t.Guard.CheckFence("Bash", probeInput); blocked {
					return actool.Errorf(fmt.Sprintf("electronic fence blocked run_poc: %s", reason)), nil
				}
			}

			timeout := p.TimeoutSeconds
			if timeout <= 0 {
				timeout = 45
			}
			if timeout > 120 {
				timeout = 120
			}
			runCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
			defer cancel()

			oobURL := ""
			if p.OOBToken != "" {
				oobURL = oobBaseURL() + "/oob/" + p.OOBToken
			}
			s.recordTaskOutbound(t, "poc", "http", p.Target, "POC", "PoC verification")

			if p.TemplatePath != "" {
				fullPath, err := resolveOfflineTemplate(nucleiTemplatesDir(), p.TemplatePath)
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				return execNucleiTemplate(runCtx, fullPath, p.Target, t.ProdSafeMode, p.TemplatePath, "", "")
			}

			var kind, name, cve, content, guidance string
			if hasInline {
				if p.InlineKind != db.PocKindNucleiYAML && p.InlineKind != db.PocKindPythonScript {
					return actool.Errorf("inline_kind must be nuclei_yaml or python_script"), nil
				}
				kind = p.InlineKind
				name = "inline-custom-poc"
				content = p.InlineContent
			} else {
				if s.m == nil || s.m.pg == nil {
					return actool.Errorf("database unavailable"), nil
				}
				poc, err := s.m.pg.GetPocByRef(p.PocRef)
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				kind = poc.Kind
				name = poc.Name
				cve = poc.CVE
				content = poc.Content
				guidance = poc.ExploitGuidance
			}

			tmpDir, err := os.MkdirTemp("", "artex-poc-*")
			if err != nil {
				return actool.Errorf(fmt.Sprintf("create temp dir: %v", err)), nil
			}
			defer os.RemoveAll(tmpDir)

			switch kind {
			case db.PocKindNucleiYAML:
				yamlPath := filepath.Join(tmpDir, "poc.yaml")
				if err := os.WriteFile(yamlPath, []byte(content), 0o600); err != nil {
					return actool.Errorf(fmt.Sprintf("write temp poc: %v", err)), nil
				}
				return execNucleiTemplate(runCtx, yamlPath, p.Target, t.ProdSafeMode, "", name, guidance)

			case db.PocKindPythonScript:
				pyPath := filepath.Join(tmpDir, "poc.py")
				if err := os.WriteFile(pyPath, []byte(content), 0o600); err != nil {
					return actool.Errorf(fmt.Sprintf("write temp poc: %v", err)), nil
				}
				return execPythonPoc(runCtx, pyPath, p.Target, p.OOBToken, oobURL, name, cve, guidance)
			default:
				return actool.Errorf(fmt.Sprintf("unsupported poc kind: %s", kind)), nil
			}
		},
	)
}

func execPythonPoc(ctx context.Context, pyPath, target, oobToken, oobURL, pocName, cve, guidance string) (actool.Result, error) {
	cmd := exec.CommandContext(ctx, "python3", pyPath, "--target", target)
	cmd.Env = append(os.Environ(),
		"ARTEX_POC_TARGET="+target,
		"ARTEX_OOB_TOKEN="+oobToken,
		"ARTEX_OOB_URL="+oobURL,
	)
	outBytes, runErr := cmd.CombinedOutput()
	exitCode := 0
	if runErr != nil {
		var ee *exec.ExitError
		if errors.As(runErr, &ee) {
			exitCode = ee.ExitCode()
		} else {
			return actool.Errorf(fmt.Sprintf("python3 exec failed: %v", runErr)), nil
		}
	}
	outStr := strings.TrimSpace(string(outBytes))
	if len(outStr) > 16384 {
		outStr = outStr[:16384] + "\n...(truncated)"
	}
	return jsonResult(map[string]any{
		"kind":             db.PocKindPythonScript,
		"poc_name":         pocName,
		"cve":              cve,
		"target":           target,
		"exit_code":        exitCode,
		"matched":          exitCode == 0 && outStr != "",
		"output":           outStr,
		"exploit_guidance": guidance,
	})
}

func (s *Server) toolSavePoc() actool.CoreTool {
	return wrTool(
		"save_poc",
		"Save a verified custom PoC (nuclei_yaml or python_script) authored during assessment into the enterprise private PoC repository for future reuse.",
		objSchema(map[string]any{
			"name":             strParam("Unique PoC identifier (e.g. 'erp-invoice-sqli-2026')"),
			"kind":             strParam("nuclei_yaml or python_script"),
			"severity":         strParam("info, low, medium, high, or critical"),
			"cve":              strParam("Optional CVE or internal advisory ID"),
			"tags":             strParam("Comma-separated tags (e.g. 'erp,sqli,intranet')"),
			"description":      strParam("Short summary of what the PoC verifies"),
			"exploit_guidance": strParam("Non-destructive secondary exploitation / proof steps after match"),
			"content":          strParam("Full Nuclei YAML template or Python3 PoC script (reads ARTEX_POC_TARGET / ARTEX_OOB_URL)"),
		}, "name", "kind", "content"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if s.m == nil || s.m.pg == nil {
				return actool.Errorf("database unavailable"), nil
			}
			var req db.UpsertPocInput
			if err := json.Unmarshal(in, &req); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			req.CreatedBy = "agent"
			rec, created, err := s.m.pg.UpsertPoc(req)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(map[string]any{"saved": true, "created": created, "poc": rec})
		},
	)
}

func execNucleiTemplate(ctx context.Context, tplPath, target string, prodSafe bool, relPath, pocName, guidance string) (actool.Result, error) {
	args := []string{"-t", tplPath, "-u", target, "-jsonl", "-nc", "-silent"}
	if prodSafe {
		args = append(args, "-rl", "10", "-c", "5")
	}
	cmd := exec.CommandContext(ctx, "nuclei", args...)
	outBytes, err := cmd.CombinedOutput()
	exitCode := 0
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			exitCode = ee.ExitCode()
		} else {
			return actool.Errorf(fmt.Sprintf("nuclei exec failed: %v", err)), nil
		}
	}
	outStr := strings.TrimSpace(string(outBytes))
	if len(outStr) > 16384 {
		outStr = outStr[:16384] + "\n...(truncated)"
	}
	return jsonResult(map[string]any{
		"kind":             db.PocKindNucleiYAML,
		"poc_name":         pocName,
		"template_path":    relPath,
		"target":           target,
		"exit_code":        exitCode,
		"matched":          exitCode == 0 && outStr != "",
		"output":           outStr,
		"exploit_guidance": guidance,
	})
}
