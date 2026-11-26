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

	// 5. Asset-driven attack surface matrix (auto-links discovered assets to uncovered hunt routes)
	if s.m.assets != nil {
		if matrix, err := s.computeTaskAssetHuntMatrix(taskID, 8); err == nil && matrix.TotalAssets > 0 {
			fmt.Fprintf(&b, "- Asset-driven hunt matrix: %d total assets (%d covered by intents, %d uncovered)\n",
				matrix.TotalAssets, matrix.CoveredAssets, matrix.UncoveredAssets)
			shown := 0
			for _, rec := range matrix.Recommendations {
				if rec.Covered && shown >= 3 {
					continue
				}
				state := "UNCOVERED"
				if rec.Covered {
					state = "covered"
				}
				ossHint := ""
				if rec.OSSCandidate != nil {
					ossHint = fmt.Sprintf(" [OSS=%s -> oss_fetch_source(%s)]", rec.OSSCandidate.Component, rec.OSSCandidate.RepoURL)
				}
				fmt.Fprintf(&b, "  -> [%s|%s] asset#%d (%s) %s tags=%v tools=%v%s\n",
					state, rec.Priority, rec.AssetID, rec.AssetType, rec.Target, rec.Tags, rec.Recommended, ossHint)
				shown++
				if shown >= 8 {
					break
				}
			}
			b.WriteString("  -> Call plan_asset_hunt(task_id) for the full prioritized matrix; prioritize UNCOVERED high-value assets before wrapping up.\n")
		}
	}

	// 6. Shared Uncertainty Blackboard & MazeRunner Stagnation Triage
	bbTriage := s.computeBlackboardTriage(t, taskID)
	if bbTriage.TotalEntries > 0 || bbTriage.StagnationDetected {
		fmt.Fprintf(&b, "- Shared Uncertainty Blackboard (Cairn/MazeRunner triage): %d entries (unblocked_ready=%d, open_bounties=%d, hypotheses=%d, anomalies=%d, quarantined_deception=%d)\n",
			bbTriage.TotalEntries, len(bbTriage.UnblockedSurfaces), len(bbTriage.OpenPreconditionNeed), len(bbTriage.ActiveHypotheses), len(bbTriage.RecentAnomalies), len(bbTriage.QuarantinedDeception))
		if bbTriage.StagnationDetected {
			fmt.Fprintf(&b, "  -> [MAZERUNNER STAGNATION / TRIAGE ALERT]: %s\n", bbTriage.StagnationReason)
		}
		for i, u := range bbTriage.UnblockedSurfaces {
			if i >= 4 {
				break
			}
			fmt.Fprintf(&b, "  -> [UNBLOCKED & READY TO RE-TEST] bb#%d (%s) target=%s topic=%q (precondition %q is now satisfied!)\n",
				u.ID, u.Kind, u.Target, u.Topic, u.PreconditionTag)
		}
		for i, p := range bbTriage.OpenPreconditionNeed {
			if i >= 4 {
				break
			}
			fmt.Fprintf(&b, "  -> [OPEN PRECONDITION BOUNTY] bb#%d target=%s need=%q topic=%q — dispatch or steer workers to locate this prerequisite\n",
				p.ID, p.Target, p.PreconditionTag, p.Topic)
		}
		for i, q := range bbTriage.QuarantinedDeception {
			if i >= 3 {
				break
			}
			fmt.Fprintf(&b, "  -> [QUARANTINED DECEPTION / CANARY WARNING] bb#%d target=%s topic=%q — DO NOT trust or report without independent out-of-band proof\n",
				q.ID, q.Target, q.Topic)
		}
	}

	// 7. Concurrent Resource & Session Leases
	if leases := globalLeaseMgr.List(t.ID); len(leases) > 0 {
		var leaseDescs []string
		for _, l := range leases {
			leaseDescs = append(leaseDescs, fmt.Sprintf("%s[%s by %s]", l.ResourceKey, l.Mode, l.Holder))
		}
		fmt.Fprintf(&b, "- Active concurrent resource/session leases: %s (avoid dispatching conflicting state-mutating intents onto exclusive_mutate resources)\n",
			strings.Join(leaseDescs, ", "))
	}

	// 8. Available PoC & wordlist inventory
	filePocs := len(loadPocsFromDir(pocsDir()))
	wlCount := 0
	if s.m.pg != nil {
		if wls, err := s.m.pg.ListWordlists(""); err == nil {
			wlCount = len(wls)
		}
	}
	fmt.Fprintf(&b, "- Enterprise tooling inventory: %d file-based PoCs in %s (use run_infra_baseline / search_pocs / run_poc), %d encrypted wordlists (use list_wordlists / run_credential_audit / run_password_spray), internal OOB callback (oob_create_token / oob_poll_hits), business-logic & traffic probes (authz_replay / race_probe / extract_web_contracts / traffic_fuzz_audit), OSS source auditing (oss_fetch_source / code_scan_semgrep), shared uncertainty blackboard & belief revision (bb_record / bb_search / bb_corroborate / invalidate_fact_cascade), concurrent session lease coordinator (resource_lease_acquire / resource_lease_release).\n",
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
