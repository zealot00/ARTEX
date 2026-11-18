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
