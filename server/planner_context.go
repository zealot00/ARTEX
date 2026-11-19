package server

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
)

// buildPlannerRuntimeContext compiles live, authoritative task posture for each
// Planner round: guardrails (fence/prod_safe/lateral_gate), pending MLPS checks,
// open persistent depth sessions, workspace source-code detection, and PoC/wordlist counts.
func (s *Server) buildPlannerRuntimeContext(taskID int64, taskDir string) string {
	if s == nil || s.m == nil || taskID <= 0 {
		return ""
	}
	t, ok := s.m.Task(strconv.FormatInt(taskID, 10))
	if !ok || t == nil {
		return ""
	}

	t.lifecycleMu.RLock()
	prodSafeMode := t.ProdSafeMode
	fenceEnabled := t.FenceEnabled
	fenceRules := append([]string(nil), t.FenceRules...)
	lateralGate := t.LateralGate
	lateralApproved := t.LateralApproved
	complianceProfile := t.ComplianceProfile
	t.lifecycleMu.RUnlock()

	var b strings.Builder
	b.WriteString("[Task runtime posture & enterprise capabilities (server-injected, authoritative)]:\n")

	// 1. Guardrails & scope posture
	fmt.Fprintf(&b, "- Guardrails: prod_safe_mode=%v, fence_enabled=%v", prodSafeMode, fenceEnabled)
	if fenceEnabled && len(fenceRules) > 0 {
		fmt.Fprintf(&b, ", fence_rules=%v", fenceRules)
	}
	fmt.Fprintf(&b, ", lateral_gate=%v, lateral_approved=%v\n", lateralGate, lateralApproved)
	if lateralGate && !lateralApproved {
		b.WriteString("  -> Lateral movement is GATED: focus on initial foothold verification; do NOT dispatch pivot/tunnel/AD-dump intents until operator approves lateral movement.\n")
	}

	// 2. MLPS 2.0 / compliance checklist progress
	if s.m.pg != nil && (strings.TrimSpace(complianceProfile) != "" || prodSafeMode) {
		if checks, err := s.m.pg.ListTaskChecks(taskID); err == nil && len(checks) > 0 {
			sum := db.SummarizeTaskChecks(checks)
			fmt.Fprintf(&b, "- Compliance (%s): %d/%d completed (passed=%d, failed=%d, na=%d, blocked=%d, pending=%d)\n",
				complianceProfile, sum.Total-sum.Pending, sum.Total, sum.Passed, sum.Failed, sum.NA, sum.Blocked, sum.Pending)
			var pendingCodes []string
			for _, c := range checks {
				if c.Status == db.CheckStatusPending {
					pendingCodes = append(pendingCodes, fmt.Sprintf("%s(%s)", c.CheckCode, c.Title))
				}
			}
			if len(pendingCodes) > 0 {
				fmt.Fprintf(&b, "  -> Pending compliance checks (dispatch intents & call record_check_result before finishing): %s\n", strings.Join(pendingCodes, ", "))
			}
		}
	}

	// 3. Open persistent depth sessions
	if s.sessMgr != nil {
		if sessions := s.sessMgr.List(t.ID); len(sessions) > 0 {
			var openList []string
			for _, sess := range sessions {
				if sess.Status == "open" {
					desc := fmt.Sprintf("%s(%s:%s)", sess.ID, sess.Kind, sess.Name)
					if sess.SocksAddr != "" {
						desc += "[socks5=" + sess.SocksAddr + "]"
					}
					openList = append(openList, desc)
				}
			}
			if len(openList) > 0 {
				fmt.Fprintf(&b, "- Active depth sessions: %s (reusable via depth_session_exec / jump_session_id / proxychains4)\n", strings.Join(openList, ", "))
			}
		}
	}

	// 4. Workspace source-code auto-detection (triggers white-box/gray-box Waves 1-4)
	if srcCount, manifests := detectWorkspaceSourceCode(taskDir); srcCount > 0 || len(manifests) > 0 {
		fmt.Fprintf(&b, "- White-box source code detected in task workspace (%s): ~%d source files, manifests=%v\n",
			taskDir, srcCount, manifests)
		b.WriteString("  -> Run structured code-audit waves using code_map_entrypoints, code_audit_deps, code_scan_sinks, code_audit_auth_gaps, code_trace_symbol, and code_read_context.\n")
	}

	// 5. Available PoC & wordlist inventory
	filePocs := len(loadPocsFromDir(pocsDir()))
	wlCount := 0
	if s.m.pg != nil {
		if wls, err := s.m.pg.ListWordlists(""); err == nil {
			wlCount = len(wls)
		}
	}
	fmt.Fprintf(&b, "- Enterprise tooling inventory: %d file-based PoCs in %s (use run_infra_baseline / search_pocs / run_poc), %d encrypted wordlists (use list_wordlists / run_credential_audit / run_password_spray), internal OOB callback (oob_create_token / oob_poll_hits), business-logic probes (authz_replay / race_probe).\n",
		filePocs, pocsDir(), wlCount)

	return b.String()
}

func detectWorkspaceSourceCode(dir string) (srcCount int, manifests []string) {
	if strings.TrimSpace(dir) == "" {
		return 0, nil
	}
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return 0, nil
	}
	visited := 0
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if path != dir && (name == ".git" || name == "node_modules" || name == "vendor" || name == "cmd-output" || name == "target" || name == "dist") {
				return filepath.SkipDir
			}
			return nil
		}
		visited++
		if visited > 500 {
			return fs.SkipAll
		}
		low := strings.ToLower(d.Name())
		switch low {
		case "pom.xml", "go.mod", "package.json", "requirements.txt", "build.gradle":
			if rel, err := filepath.Rel(dir, path); err == nil {
				manifests = append(manifests, filepath.ToSlash(rel))
			}
		}
		switch strings.ToLower(filepath.Ext(low)) {
		case ".java", ".go", ".py", ".ts", ".tsx", ".js", ".jsx", ".php", ".cs", ".rb", ".kt":
			srcCount++
		}
		return nil
	})
	return srcCount, manifests
}
