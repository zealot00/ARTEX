package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/report"
	actool "github.com/Autumn-27/norma/tool"
)

func (s *Server) complianceTools() []actool.CoreTool {
	return []actool.CoreTool{
		s.toolListTaskChecks(),
		s.toolRecordCheckResult(),
	}
}

func (s *Server) seedComplianceTools() {
	if s.m == nil || s.m.pg == nil {
		return
	}
	agents, _ := json.Marshal([]string{"worker", "planner", "main", "auto", "pentest"})
	for _, t := range s.complianceTools() {
		schema, _ := json.Marshal(t.InputSchema())
		if err := s.m.pg.SeedTool(t.Name(), t.Description(), schema, agents); err != nil {
			log.Printf("[compliance] seed tool %s: %v", t.Name(), err)
		}
	}
}

func (s *Server) toolListTaskChecks() actool.CoreTool {
	return roTool(
		"list_task_checks",
		"List all compliance penetration-test checklist items (e.g. MLPS 2.0 domains) and their current status (pending/passed/failed/na/blocked) for a task. Use this to see which domains still need testing and negative-evidence recording.",
		objSchema(map[string]any{
			"task_id": strParam("Task ID (numeric string)"),
		}, "task_id"),
		func(_ context.Context, raw json.RawMessage) (actool.Result, error) {
			var a struct {
				TaskID string `json:"task_id"`
			}
			if err := json.Unmarshal(raw, &a); err != nil {
				return actool.Errorf(fmt.Sprintf("bad args: %v", err)), nil
			}
			id, err := strconv.ParseInt(strings.TrimSpace(a.TaskID), 10, 64)
			if err != nil || id <= 0 {
				return actool.Errorf(fmt.Sprintf("invalid task_id %q", a.TaskID)), nil
			}
			checks, err := s.m.PG().ListTaskChecks(id)
			if err != nil {
				return actool.Errorf(fmt.Sprintf("list checks: %v", err)), nil
			}
			return jsonResult(map[string]any{
				"task_id": a.TaskID,
				"summary": db.SummarizeTaskChecks(checks),
				"checks":  checks,
			})
		},
	)
}

func (s *Server) toolRecordCheckResult() actool.CoreTool {
	return wrTool(
		"record_check_result",
		"Record the penetration test verdict for a compliance checklist item (such as MLPS 2.0 NET-TLS, AUTH-WEAKPWD, AUTH-ACCESS, SVC-UNAUTH, etc.). Always record both positive findings (status='failed' with finding_id) AND negative verified results (status='passed' with exact command/HTTP observation in evidence).",
		objSchema(map[string]any{
			"task_id":    strParam("Task ID (numeric string)"),
			"check_code": strParam("Checklist item code, e.g. NET-TLS, NET-BOUNDARY, AUTH-WEAKPWD, AUTH-SESSION, AUTH-ACCESS, WEB-INJECTION, WEB-XSS-CSRF, APP-API, SVC-UNAUTH, SEC-PROD-SAFE"),
			"status":     map[string]any{"type": "string", "enum": []string{"passed", "failed", "na", "blocked", "pending"}, "description": "Verdict: passed (tested & no vulnerability), failed (vulnerability confirmed), na (not applicable), blocked"},
			"target":     strParam("Optional tested host/URL/service target (empty = task-wide)"),
			"evidence":   strParam("Concrete command output, HTTP status/headers, or verification observation proving the verdict"),
			"notes":      strParam("Optional additional notes or remediation context"),
			"finding_id": map[string]any{"type": "integer", "description": "Optional standalone finding_id when status='failed'"},
			"tested_by":  strParam("Optional actor/agent label (e.g. worker, planner)"),
		}, "task_id", "check_code", "status", "evidence"),
		func(_ context.Context, raw json.RawMessage) (actool.Result, error) {
			var a struct {
				TaskID    string `json:"task_id"`
				CheckCode string `json:"check_code"`
				Status    string `json:"status"`
				Target    string `json:"target"`
				Evidence  string `json:"evidence"`
				Notes     string `json:"notes"`
				FindingID *int64 `json:"finding_id"`
				TestedBy  string `json:"tested_by"`
			}
			if err := json.Unmarshal(raw, &a); err != nil {
				return actool.Errorf(fmt.Sprintf("bad args: %v", err)), nil
			}
			id, err := strconv.ParseInt(strings.TrimSpace(a.TaskID), 10, 64)
			if err != nil || id <= 0 {
				return actool.Errorf(fmt.Sprintf("invalid task_id %q", a.TaskID)), nil
			}
			if strings.TrimSpace(a.TestedBy) == "" {
				a.TestedBy = "agent"
			}
			chk, err := s.m.PG().UpsertTaskCheckResult(id, db.TaskCheckInput{
				CheckCode: a.CheckCode,
				Status:    a.Status,
				Target:    a.Target,
				Evidence:  a.Evidence,
				Notes:     a.Notes,
				FindingID: a.FindingID,
				TestedBy:  a.TestedBy,
			})
			if err != nil {
				return actool.Errorf(fmt.Sprintf("record check: %v", err)), nil
			}
			return jsonResult(chk)
		},
	)
}

func (s *Server) applyProdSafeTaskSetup(t *Task) {
	if t == nil || !t.ProdSafeMode || t.Store == nil {
		return
	}
	_, _ = t.Store.AddConstraint("deny",
		"【等保生产安全基线】严禁执行 DoS/压测工具（hping3/ab/wrk/siege/locust/slowloris）、高并发暴力发包（ffuf -t<=20, hydra -t<=4）、sqlmap --os-shell/--sql-shell/--risk=3 及任何删库/篡改/破坏业务连续性的操作。",
		"system")
	_, _ = t.Store.AddConstraint("allow",
		"【等保合规留痕】对已测试的等保检查项（含未检出漏洞的阴性验证），调用 record_check_result 记录 passed/failed/na 结论与实测证据，并在任务结束前检查 list_task_checks。",
		"system")
}

func (s *Server) listTaskChecks(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	taskID, _ := strconv.ParseInt(t.ID, 10, 64)
	checks, err := s.m.PG().ListTaskChecks(taskID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{
		"task_id":            t.ID,
		"compliance_profile": t.ComplianceProfile,
		"prod_safe_mode":     t.ProdSafeMode,
		"summary":            db.SummarizeTaskChecks(checks),
		"checks":             checks,
	})
}

func (s *Server) upsertTaskCheck(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	var req struct {
		Domain    string `json:"domain"`
		Title     string `json:"title"`
		Status    string `json:"status"`
		Target    string `json:"target"`
		Evidence  string `json:"evidence"`
		Notes     string `json:"notes"`
		FindingID *int64 `json:"finding_id"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	taskID, _ := strconv.ParseInt(t.ID, 10, 64)
	chk, err := s.m.PG().UpsertTaskCheckResult(taskID, db.TaskCheckInput{
		CheckCode: r.PathValue("code"),
		Domain:    req.Domain,
		Title:     req.Title,
		Status:    req.Status,
		Target:    req.Target,
		Evidence:  req.Evidence,
		Notes:     req.Notes,
		FindingID: req.FindingID,
		TestedBy:  s.approver(r),
	})
	if err != nil {
		if errors.Is(err, db.ErrInvalidCheckCode) || errors.Is(err, db.ErrInvalidCheckStatus) {
			writeErr(w, 400, err.Error())
			return
		}
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, chk)
}

func (s *Server) getMLPSReport(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	taskID, _ := strconv.ParseInt(t.ID, 10, 64)
	checks, err := s.m.PG().ListTaskChecks(taskID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	findings, _ := t.Store.ListByKind(db.KindFinding, 1000)
	counts := map[string]int{}
	if as := s.m.Assets(); as != nil {
		for _, ty := range []string{"root_domain", "ip", "subdomain", "app", "service", "endpoint"} {
			ns, _ := as.QueryByType(ty, 100000, 0)
			if len(ns) > 0 {
				counts[ty] = len(ns)
			}
		}
	}
	md := report.MLPSMarkdown(report.MLPSInput{
		TaskID:            t.ID,
		ExternalRef:       t.ExternalRef,
		Title:             t.Description,
		Goal:              t.Goal,
		ComplianceProfile: t.ComplianceProfile,
		ProdSafeMode:      t.ProdSafeMode,
		GeneratedAt:       time.Now(),
		AssetCounts:       counts,
		Checks:            checks,
		Findings:          findings,
	})
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.WriteHeader(200)
	_, _ = w.Write([]byte(md))
}
