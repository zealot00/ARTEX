package server

import (
	"bufio"
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
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

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

func pocsDir() string {
	if v := strings.TrimSpace(os.Getenv("ARTEX_POCS_DIR")); v != "" {
		return v
	}
	for _, dir := range []string{"./pocs", "/app/pocs", "../pocs"} {
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			return dir
		}
	}
	return "./pocs"
}

// loadPocsFromDir dynamically loads .yaml (Nuclei) and .py (Python) PoCs from root.
// Supports optional '# artex-*:' header comments and falls back to native Nuclei YAML fields or filename.
func loadPocsFromDir(root string) []db.UpsertPocInput {
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return nil
	}
	var files []string
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		low := strings.ToLower(d.Name())
		if strings.HasSuffix(low, ".yaml") || strings.HasSuffix(low, ".yml") || strings.HasSuffix(low, ".py") {
			files = append(files, path)
		}
		return nil
	})
	sort.Strings(files)

	out := make([]db.UpsertPocInput, 0, len(files))
	for _, f := range files {
		rawBytes, err := os.ReadFile(f)
		if err != nil || len(rawBytes) == 0 {
			continue
		}
		content := string(rawBytes)
		low := strings.ToLower(f)
		kind := db.PocKindNucleiYAML
		if strings.HasSuffix(low, ".py") {
			kind = db.PocKindPythonScript
		}
		baseName := strings.TrimSuffix(filepath.Base(f), filepath.Ext(f))
		relDir := ""
		if rel, err := filepath.Rel(root, filepath.Dir(f)); err == nil && rel != "." {
			relDir = strings.ReplaceAll(filepath.ToSlash(rel), "/", ",")
		}

		p := db.UpsertPocInput{
			Name:      baseName,
			Kind:      kind,
			Severity:  "medium",
			Tags:      relDir,
			Content:   content,
			CreatedBy: "file",
		}

		sc := bufio.NewScanner(strings.NewReader(content))
		for lineNo := 0; sc.Scan() && lineNo < 30; lineNo++ {
			line := strings.TrimSpace(sc.Text())
			if strings.HasPrefix(line, "#") {
				body := strings.TrimSpace(strings.TrimPrefix(line, "#"))
				if kv := strings.SplitN(body, ":", 2); len(kv) == 2 {
					k := strings.ToLower(strings.TrimSpace(kv[0]))
					v := strings.TrimSpace(kv[1])
					switch k {
					case "artex-name":
						if v != "" {
							p.Name = v
						}
					case "artex-severity":
						if v != "" {
							p.Severity = strings.ToLower(v)
						}
					case "artex-cve":
						p.CVE = v
					case "artex-tags":
						if v != "" {
							p.Tags = v
						}
					case "artex-desc":
						p.Description = v
					case "artex-guidance":
						p.ExploitGuidance = v
					}
				}
				continue
			}
			// Fallback metadata extraction for plain Nuclei YAML templates without artex-* headers.
			if kind == db.PocKindNucleiYAML {
				if strings.HasPrefix(line, "id:") && p.Name == baseName {
					if v := strings.TrimSpace(strings.TrimPrefix(line, "id:")); v != "" {
						p.Name = v
					}
				} else if strings.HasPrefix(line, "severity:") && p.Severity == "medium" {
					if v := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(line, "severity:"))); v != "" {
						p.Severity = v
					}
				} else if strings.HasPrefix(line, "name:") && p.Description == "" {
					p.Description = strings.TrimSpace(strings.TrimPrefix(line, "name:"))
				}
			}
		}
		out = append(out, p)
	}
	return out
}

func defaultIntranetPocs() []db.UpsertPocInput {
	return loadPocsFromDir(pocsDir())
}

// GET /api/pocs — admin JWT only.
func (s *Server) listPocs(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdminJWT(w, r) {
		return
	}
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
	if !s.requireAdminJWT(w, r) {
		return
	}
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
	if !s.requireAdminJWT(w, r) {
		return
	}
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
		s.toolRunInfraBaseline(),
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
	for _, d := range loadPocsFromDir(pocsDir()) {
		if _, err := s.m.pg.GetPocByRef(d.Name); err == nil {
			continue
		}
		if _, _, err := s.m.pg.UpsertPoc(d); err != nil {
			log.Printf("[pocs] seed default %s: %v", d.Name, err)
		}
	}
}

func matchFilePoc(p db.UpsertPocInput, query, kind, tag string) bool {
	if kind != "" && !strings.EqualFold(p.Kind, kind) {
		return false
	}
	if tag != "" {
		found := false
		for _, t := range strings.Split(strings.ToLower(p.Tags), ",") {
			if strings.TrimSpace(t) == tag {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if query != "" {
		hay := strings.ToLower(p.Name + " " + p.CVE + " " + p.Tags + " " + p.Description)
		if !strings.Contains(hay, query) {
			return false
		}
	}
	return true
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
		"Search enterprise PoCs (both PostgreSQL private repo and hot-loaded ./pocs directory) and offline nuclei-templates (/opt/nuclei-templates) by keyword, CVE, kind, or tag. Use results with run_poc for verification and chained secondary exploitation.",
		objSchema(map[string]any{
			"query": strParam("Keyword, product/tech name, or CVE (e.g. 'k8s', 'samba', 'postgresql', 'CVE-2024')"),
			"kind":  strParam("Optional filter for private PoCs: nuclei_yaml or python_script"),
			"tag":   strParam("Optional tag filter (e.g. 'rce', 'k8s', 'samba', 'db', 'infra')"),
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
			q := strings.ToLower(strings.TrimSpace(p.Query))
			k := strings.ToLower(strings.TrimSpace(p.Kind))
			tg := strings.ToLower(strings.TrimSpace(p.Tag))

			var privatePocs []db.PocRecord
			seen := map[string]bool{}
			if s.m != nil && s.m.pg != nil {
				items, err := s.m.pg.SearchPocs(p.Query, p.Kind, p.Tag, 50)
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				for _, it := range items {
					privatePocs = append(privatePocs, it)
					seen[it.Name] = true
				}
			}
			// Hot-load any newly dropped files from pocs/ directory without requiring a restart.
			for _, fp := range loadPocsFromDir(pocsDir()) {
				if seen[fp.Name] || !matchFilePoc(fp, q, k, tg) {
					continue
				}
				seen[fp.Name] = true
				privatePocs = append(privatePocs, db.PocRecord{
					Name:            fp.Name,
					Kind:            fp.Kind,
					Severity:        fp.Severity,
					CVE:             fp.CVE,
					Tags:            fp.Tags,
					Description:     fp.Description,
					ExploitGuidance: fp.ExploitGuidance,
					CreatedBy:       fp.CreatedBy,
				})
				if len(privatePocs) >= 50 {
					break
				}
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
				"pocs_dir":                   pocsDir(),
				"offline_nuclei_templates":   offline,
				"offline_templates_root_dir": nucleiTemplatesDir(),
			})
		},
	)
}

func validatePocTarget(target string) error {
	if target == "" {
		return errors.New("target is required")
	}
	if strings.HasPrefix(target, "-") {
		return fmt.Errorf("invalid target %q: leading '-' is not allowed", target)
	}
	for _, r := range target {
		if unicode.IsSpace(r) || r < 0x20 || r == 0x7f {
			return fmt.Errorf("invalid target %q: whitespace or control characters are not allowed", target)
		}
	}
	return nil
}

func (s *Server) toolRunPoc() actool.CoreTool {
	return wrTool(
		"run_poc",
		"Execute an enterprise PoC (poc_ref from DB or hot-loaded ./pocs dir), an offline nuclei template (template_path), or a custom agent-authored inline PoC (inline_kind + inline_content) against an authorized target. Enforces electronic fence and prod_safe_mode, injects optional OOB callback token/URL, and returns exploit_guidance.",
		objSchema(map[string]any{
			"task_id":         strParam("Task ID (numeric string)"),
			"target":          strParam("Authorized target URL or host:port (e.g. 'http://10.10.1.5:8080' or '10.10.1.5:5432')"),
			"poc_ref":         strParam("Enterprise PoC numeric ID or exact name (mutually exclusive with template_path / inline_content)"),
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

			if err := validatePocTarget(p.Target); err != nil {
				return actool.Errorf(err.Error()), nil
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
				var resolved bool
				if s.m != nil && s.m.pg != nil {
					if poc, err := s.m.pg.GetPocByRef(p.PocRef); err == nil && poc != nil {
						kind = poc.Kind
						name = poc.Name
						cve = poc.CVE
						content = poc.Content
						guidance = poc.ExploitGuidance
						resolved = true
					}
				}
				if !resolved {
					for _, fp := range loadPocsFromDir(pocsDir()) {
						if strings.EqualFold(fp.Name, p.PocRef) {
							kind = fp.Kind
							name = fp.Name
							cve = fp.CVE
							content = fp.Content
							guidance = fp.ExploitGuidance
							resolved = true
							break
						}
					}
				}
				if !resolved {
					return actool.Errorf(fmt.Sprintf("poc %q not found in database or %s", p.PocRef, pocsDir())), nil
				}
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
			req.Name = strings.TrimSpace(req.Name)
			if existing, err := s.m.pg.GetPocByRef(req.Name); err == nil && existing != nil && existing.CreatedBy != "agent" {
				return actool.Errorf(fmt.Sprintf("cannot overwrite non-agent PoC %q (owned by %s); choose a new name", existing.Name, existing.CreatedBy)), nil
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

var portToInfraTags = map[int][]string{
	21:    {"ftp"},
	22:    {"ssh"},
	25:    {"smtp"},
	53:    {"dns"},
	123:   {"ntp"},
	161:   {"snmp"},
	389:   {"ldap"},
	443:   {"tls"},
	445:   {"samba"},
	587:   {"smtp"},
	631:   {"print"},
	636:   {"ldap", "tls"},
	873:   {"rsync"},
	2049:  {"nfs"},
	2181:  {"zookeeper"},
	2375:  {"docker"},
	2379:  {"etcd"},
	3306:  {"mysql"},
	4646:  {"nomad"},
	5000:  {"openstack", "docker"},
	5432:  {"postgresql"},
	5984:  {"couchdb"},
	6379:  {"redis"},
	6443:  {"k8s", "apiserver"},
	7474:  {"neo4j"},
	8001:  {"kong"},
	8086:  {"influxdb"},
	8088:  {"hadoop"},
	8123:  {"clickhouse"},
	8161:  {"activemq"},
	8200:  {"vault"},
	8848:  {"nacos"},
	9000:  {"minio", "sonarqube"},
	9100:  {"print"},
	9180:  {"apisix"},
	9200:  {"elasticsearch"},
	9870:  {"hadoop"},
	10250: {"kubelet"},
	10255: {"kubelet"},
	11211: {"memcached"},
	15672: {"rabbitmq"},
	26379: {"sentinel"},
	27017: {"mongodb"},
}

func matchBaselinePocs(all []db.UpsertPocInput, ports []int, techs []string, maxCount int) []db.UpsertPocInput {
	wantTags := map[string]bool{}
	for _, port := range ports {
		for _, tg := range portToInfraTags[port] {
			wantTags[tg] = true
		}
	}
	for _, tc := range techs {
		if v := strings.ToLower(strings.TrimSpace(tc)); v != "" {
			wantTags[v] = true
		}
	}
	if len(wantTags) == 0 {
		return nil
	}
	var matched []db.UpsertPocInput
	seen := map[string]bool{}
	for _, p := range all {
		if seen[p.Name] {
			continue
		}
		hay := strings.ToLower(p.Name + "," + p.Tags)
		hit := false
		for tg := range wantTags {
			if strings.Contains(hay, tg) {
				hit = true
				break
			}
		}
		if hit {
			seen[p.Name] = true
			matched = append(matched, p)
			if len(matched) >= maxCount {
				break
			}
		}
	}
	return matched
}

func (s *Server) toolRunInfraBaseline() actool.CoreTool {
	return wrTool(
		"run_infra_baseline",
		"Port- and fingerprint-driven batch PoC runner: automatically maps open ports (e.g. [22,445,5432,6379,6443,10250,2379]) and detected technologies (e.g. ['spring','nacos','k8s','samba']) to matching PoCs in ./pocs/, executes them under electronic fence and prod_safe_mode caps, and returns a consolidated pass/fail audit summary.",
		objSchema(map[string]any{
			"task_id":  strParam("Task ID (numeric string)"),
			"target":   strParam("Authorized target host/IP or base URL (e.g. '10.10.1.5' or 'http://10.10.1.5:8080')"),
			"ports":    map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "Optional list of open ports discovered on target"},
			"techs":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Optional list of technology/service tags (e.g. 'spring', 'k8s', 'samba', 'redis')"},
			"max_pocs": map[string]any{"type": "integer", "description": "Maximum PoCs to run in one batch (default 8, max 12; capped at 6 in prod_safe_mode)"},
		}, "task_id", "target"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var p struct {
				TaskID  string   `json:"task_id"`
				Target  string   `json:"target"`
				Ports   []int    `json:"ports"`
				Techs   []string `json:"techs"`
				MaxPocs int      `json:"max_pocs"`
			}
			if err := json.Unmarshal(in, &p); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			p.Target = strings.TrimSpace(p.Target)
			if err := validatePocTarget(p.Target); err != nil {
				return actool.Errorf(err.Error()), nil
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
					return actool.Errorf(fmt.Sprintf("electronic fence blocked run_infra_baseline: %s", reason)), nil
				}
			}

			limit := p.MaxPocs
			if limit <= 0 {
				limit = 8
			}
			capLimit := 12
			if t.ProdSafeMode {
				capLimit = 6
			}
			if limit > capLimit {
				limit = capLimit
			}

			candidates := matchBaselinePocs(loadPocsFromDir(pocsDir()), p.Ports, p.Techs, limit)
			if len(candidates) == 0 {
				return jsonResult(map[string]any{
					"target":        p.Target,
					"executed":      0,
					"matched_count": 0,
					"results":       []any{},
					"note":          "No matching PoCs found for the provided ports/techs; call search_pocs or author an inline PoC via run_poc.",
				})
			}

			s.recordTaskOutbound(t, "infra_baseline", "mixed", p.Target, "BASELINE", "Automated port/tech PoC baseline")
			tmpDir, err := os.MkdirTemp("", "artex-baseline-*")
			if err != nil {
				return actool.Errorf(fmt.Sprintf("create temp dir: %v", err)), nil
			}
			defer os.RemoveAll(tmpDir)

			type itemSummary struct {
				Name     string `json:"name"`
				Kind     string `json:"kind"`
				Severity string `json:"severity"`
				Matched  bool   `json:"matched"`
				Output   string `json:"output,omitempty"`
				Guidance string `json:"exploit_guidance,omitempty"`
				Error    string `json:"error,omitempty"`
			}
			var results []itemSummary
			matchedCount := 0

			for i, poc := range candidates {
				runCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
				var res actool.Result
				var runErr error
				switch poc.Kind {
				case db.PocKindPythonScript:
					pyPath := filepath.Join(tmpDir, fmt.Sprintf("poc_%d.py", i))
					_ = os.WriteFile(pyPath, []byte(poc.Content), 0o600)
					res, runErr = execPythonPoc(runCtx, pyPath, p.Target, "", "", poc.Name, poc.CVE, poc.ExploitGuidance)
				case db.PocKindNucleiYAML:
					yamlPath := filepath.Join(tmpDir, fmt.Sprintf("poc_%d.yaml", i))
					_ = os.WriteFile(yamlPath, []byte(poc.Content), 0o600)
					res, runErr = execNucleiTemplate(runCtx, yamlPath, p.Target, t.ProdSafeMode, "", poc.Name, poc.ExploitGuidance)
				}
				cancel()

				item := itemSummary{
					Name:     poc.Name,
					Kind:     poc.Kind,
					Severity: poc.Severity,
					Guidance: poc.ExploitGuidance,
				}
				if runErr != nil {
					item.Error = runErr.Error()
				} else if res.IsError {
					var sb strings.Builder
					for _, b := range res.Content {
						sb.WriteString(b.Text)
					}
					item.Error = sb.String()
				} else {
					var parsed struct {
						Matched bool   `json:"matched"`
						Output  string `json:"output"`
					}
					var sb strings.Builder
					for _, b := range res.Content {
						sb.WriteString(b.Text)
					}
					_ = json.Unmarshal([]byte(sb.String()), &parsed)
					item.Matched = parsed.Matched
					if len(parsed.Output) > 1024 {
						item.Output = parsed.Output[:1024] + "...(truncated)"
					} else {
						item.Output = parsed.Output
					}
					if item.Matched {
						matchedCount++
					}
				}
				results = append(results, item)
			}

			return jsonResult(map[string]any{
				"target":        p.Target,
				"executed":      len(results),
				"matched_count": matchedCount,
				"results":       results,
			})
		},
	)
}
