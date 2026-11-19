package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"path/filepath"
	"strings"

	"github.com/Autumn-27/artex/codeaudit"
	actool "github.com/Autumn-27/norma/tool"
)

func (s *Server) codeAuditTools() []actool.CoreTool {
	return []actool.CoreTool{
		s.toolCodeMapEntrypoints(),
		s.toolCodeScanSinks(),
		s.toolCodeAuditAuthGaps(),
		s.toolCodeTraceSymbol(),
		s.toolCodeReadContext(),
		s.toolCodeAuditDeps(),
	}
}

func (s *Server) seedCodeAuditTools() {
	if s.m == nil || s.m.pg == nil {
		return
	}
	agents, _ := json.Marshal([]string{"worker", "planner", "main", "auto", "pentest"})
	for _, t := range s.codeAuditTools() {
		schema, _ := json.Marshal(t.InputSchema())
		if err := s.m.pg.SeedTool(t.Name(), t.Description(), schema, agents); err != nil {
			log.Printf("[codeaudit] seed tool %s: %v", t.Name(), err)
		}
	}
}

func (s *Server) resolveTaskAuditDir(taskID, subPath string) (string, error) {
	t := s.m.ResolveTask(strings.TrimSpace(taskID))
	if t == nil {
		return "", fmt.Errorf("task not found")
	}
	base := ""
	if s.m != nil && strings.TrimSpace(s.m.dir) != "" {
		base = filepath.Join(s.m.dir, "tasks", t.ID)
	}
	if base == "" {
		return "", fmt.Errorf("task workspace unavailable")
	}
	return codeaudit.SafeResolveDir(base, subPath)
}

func (s *Server) toolCodeMapEntrypoints() actool.CoreTool {
	return roTool(
		"code_map_entrypoints",
		"Static white-box inventory tool (Wave 1): scans production source code in the task workspace to map HTTP/RPC routes (Spring, Go, Python, Express, Laravel), shared auth middleware/filters, and auth whitelist bypass surfaces (permitAll, excludePathPatterns, @Anonymous).",
		objSchema(map[string]any{
			"task_id": strParam("Task ID (numeric string)"),
			"path":    strParam("Relative directory inside the task workspace (default '.')"),
			"limit":   map[string]any{"type": "integer", "description": "Max entries to return (default 100, max 120)"},
		}, "task_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var p struct {
				TaskID string `json:"task_id"`
				Path   string `json:"path"`
				Limit  int    `json:"limit"`
			}
			if err := json.Unmarshal(in, &p); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			dir, err := s.resolveTaskAuditDir(p.TaskID, p.Path)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			hits, err := codeaudit.MapEntrypoints(dir, p.Limit)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if hits == nil {
				hits = []codeaudit.EntrypointHit{}
			}
			return jsonResult(map[string]any{"count": len(hits), "entrypoints": hits})
		},
	)
}

func (s *Server) toolCodeScanSinks() actool.CoreTool {
	return roTool(
		"code_scan_sinks",
		"Static white-box sink scanner (Wave 2): scans production source code in the task workspace for dangerous sinks and business-logic anti-patterns (categories: sqli, cmdi, deser, ssrf, path_file, ssti_el, auth_biz, secrets) with exact file:line citations.",
		objSchema(map[string]any{
			"task_id":    strParam("Task ID (numeric string)"),
			"path":       strParam("Relative directory inside the task workspace (default '.')"),
			"categories": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Optional filter: sqli, cmdi, deser, ssrf, path_file, ssti_el, auth_biz, secrets"},
			"limit":      map[string]any{"type": "integer", "description": "Max hits to return (default 100, max 120)"},
		}, "task_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var p struct {
				TaskID     string   `json:"task_id"`
				Path       string   `json:"path"`
				Categories []string `json:"categories"`
				Limit      int      `json:"limit"`
			}
			if err := json.Unmarshal(in, &p); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			dir, err := s.resolveTaskAuditDir(p.TaskID, p.Path)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			hits, err := codeaudit.ScanSinks(dir, p.Categories, p.Limit)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if hits == nil {
				hits = []codeaudit.SinkHit{}
			}
			return jsonResult(map[string]any{"count": len(hits), "sinks": hits})
		},
	)
}

func (s *Server) toolCodeTraceSymbol() actool.CoreTool {
	return roTool(
		"code_trace_symbol",
		"Cross-file symbol definition and caller tracer (Wave 3): locates definitions and call-sites for a function, method, sink helper, or sanitizer across production source code in the task workspace.",
		objSchema(map[string]any{
			"task_id": strParam("Task ID (numeric string)"),
			"path":    strParam("Relative directory inside the task workspace (default '.')"),
			"symbol":  strParam("Exact function, method, class, or sanitizer identifier to trace"),
			"limit":   map[string]any{"type": "integer", "description": "Max references to return (default 80, max 120)"},
		}, "task_id", "symbol"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var p struct {
				TaskID string `json:"task_id"`
				Path   string `json:"path"`
				Symbol string `json:"symbol"`
				Limit  int    `json:"limit"`
			}
			if err := json.Unmarshal(in, &p); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			dir, err := s.resolveTaskAuditDir(p.TaskID, p.Path)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			refs, err := codeaudit.TraceSymbol(dir, p.Symbol, p.Limit)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if refs == nil {
				refs = []codeaudit.SymbolRef{}
			}
			return jsonResult(map[string]any{"symbol": p.Symbol, "count": len(refs), "references": refs})
		},
	)
}

func (s *Server) toolCodeAuditDeps() actool.CoreTool {
	return roTool(
		"code_audit_deps",
		"Dependency & SCA scanner: parses go.mod, package.json, pom.xml, and requirements.txt in the task workspace to flag high-risk libraries (fastjson, log4j-core, shiro-core, snakeyaml, commons-collections, jackson-databind, etc.).",
		objSchema(map[string]any{
			"task_id": strParam("Task ID (numeric string)"),
			"path":    strParam("Relative directory inside the task workspace (default '.')"),
		}, "task_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var p struct {
				TaskID string `json:"task_id"`
				Path   string `json:"path"`
			}
			if err := json.Unmarshal(in, &p); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			dir, err := s.resolveTaskAuditDir(p.TaskID, p.Path)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			advs, manifests, err := codeaudit.AuditDependencies(dir)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if advs == nil {
				advs = []codeaudit.DepAdvisory{}
			}
			if manifests == nil {
				manifests = []string{}
			}
			return jsonResult(map[string]any{"manifests": manifests, "advisories": advs})
		},
	)
}

func (s *Server) toolCodeAuditAuthGaps() actool.CoreTool {
	return roTool(
		"code_audit_auth_gaps",
		"Cross-checks discovered route handlers against surrounding +/-15 line windows for explicit auth annotations/guards and user/tenant ownership checks, flagging unguarded routes and potential IDOR/BOLA handlers.",
		objSchema(map[string]any{
			"task_id": strParam("Task ID (numeric string)"),
			"path":    strParam("Relative directory inside the task workspace (default '.')"),
			"limit":   map[string]any{"type": "integer", "description": "Max hits to return (default 80, max 120)"},
		}, "task_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var p struct {
				TaskID string `json:"task_id"`
				Path   string `json:"path"`
				Limit  int    `json:"limit"`
			}
			if err := json.Unmarshal(in, &p); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			dir, err := s.resolveTaskAuditDir(p.TaskID, p.Path)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			hits, err := codeaudit.AuditAuthGaps(dir, p.Limit)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if hits == nil {
				hits = []codeaudit.AuthGapHit{}
			}
			return jsonResult(map[string]any{"count": len(hits), "auth_gaps": hits})
		},
	)
}

func (s *Server) toolCodeReadContext() actool.CoreTool {
	return roTool(
		"code_read_context",
		"Read numbered source code lines (+/- radius around a target line) from a file strictly inside the task workspace to inspect full handler/sanitizer implementations after code_scan_sinks or code_audit_auth_gaps.",
		objSchema(map[string]any{
			"task_id": strParam("Task ID (numeric string)"),
			"file":    strParam("Relative file path inside the task workspace"),
			"line":    map[string]any{"type": "integer", "description": "1-based center line number"},
			"radius":  map[string]any{"type": "integer", "description": "Lines before and after center line (default 25, max 40)"},
		}, "task_id", "file", "line"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var p struct {
				TaskID string `json:"task_id"`
				File   string `json:"file"`
				Line   int    `json:"line"`
				Radius int    `json:"radius"`
			}
			if err := json.Unmarshal(in, &p); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			root, err := s.resolveTaskAuditDir(p.TaskID, ".")
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			snippet, startLine, endLine, err := codeaudit.ReadSourceContext(root, p.File, p.Line, p.Radius)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(map[string]any{
				"file":       p.File,
				"start_line": startLine,
				"end_line":   endLine,
				"content":    snippet,
			})
		},
	)
}
