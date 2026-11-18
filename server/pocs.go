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
	if err := decode(r, &req); err != nil {
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
	defaults := []db.UpsertPocInput{
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
	}
	for _, d := range defaults {
		if _, err := s.m.pg.GetPocByRef(d.Name); err == nil {
			continue
		}
		if _, _, err := s.m.pg.UpsertPoc(d); err != nil {
			log.Printf("[pocs] seed default %s: %v", d.Name, err)
		}
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
