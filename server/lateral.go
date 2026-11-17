package server

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
)

const schedKeyLastLateralFinding = "last_lateral_finding_id"

var defaultFootholdKeywords = []string{
	"rce", "remote_code", "command_injection", "cmd_exec", "code_exec",
	"ssrf", "sqli", "sql_injection", "auth_bypass", "cred", "secret",
	"file_upload", "deserializ", "ssti", "xxe", "unauth", "admin", "ssh",
}

// MatchesFootholdFinding reports whether a newly confirmed finding qualifies as
// a lateral-movement foothold according to classes (or default high-impact classes).
func MatchesFootholdFinding(e db.TaskEvent, classes []string) bool {
	vc := strings.ToLower(strings.TrimSpace(e.VulnClass))
	sev := strings.ToLower(strings.TrimSpace(e.Severity))
	summary := strings.ToLower(strings.TrimSpace(e.Summary))
	if len(classes) > 0 {
		for _, raw := range classes {
			c := strings.ToLower(strings.TrimSpace(raw))
			if c == "" {
				continue
			}
			if c == "*" || c == "any" {
				return true
			}
			if strings.Contains(vc, c) || strings.Contains(summary, c) {
				return true
			}
		}
		return false
	}
	if sev == "critical" || sev == "high" {
		return true
	}
	for _, kw := range defaultFootholdKeywords {
		if strings.Contains(vc, kw) {
			return true
		}
	}
	return false
}

func (sc *Scheduler) reconcileFootholdParkings() {
	lastStr := sc.mustState(schedKeyLastLateralFinding)
	if lastStr == "" {
		var maxID int64
		if evs, err := sc.pg.NewFindingsSince(0); err == nil {
			for _, e := range evs {
				if e.NodeID > maxID {
					maxID = e.NodeID
				}
			}
		}
		_ = sc.pg.SetSchedState(schedKeyLastLateralFinding, strconv.FormatInt(maxID, 10))
		return
	}
	last, _ := strconv.ParseInt(lastStr, 10, 64)
	events, err := sc.pg.NewFindingsSince(last)
	if err != nil || len(events) == 0 {
		return
	}
	maxID := last
	for _, e := range events {
		if e.NodeID > maxID {
			maxID = e.NodeID
		}
		sc.s.processFootholdFinding(e)
	}
	_ = sc.pg.SetSchedState(schedKeyLastLateralFinding, strconv.FormatInt(maxID, 10))
}

func (s *Server) processFootholdFinding(e db.TaskEvent) {
	if s.m == nil {
		return
	}
	for _, t := range s.m.List() {
		lifecycle := t.lifecycleSnapshot()
		if isTerminalStatus(lifecycle.Status) {
			continue
		}
		// Case 1: standby lateral work order waiting on upstream task e.TaskID.
		if t.AwaitingFootholdTaskID != nil && *t.AwaitingFootholdTaskID == e.TaskID && lifecycle.Paused && !t.LateralApproved {
			if !MatchesFootholdFinding(e, t.FootholdVulnClasses) {
				continue
			}
			s.injectFootholdHint(t, e)
			tid, _ := strconv.ParseInt(t.ID, 10, 64)
			if !t.LateralGate {
				_ = s.m.pg.SetTaskLateralState(tid, true, "")
				t.LateralApproved = true
				t.ParkedReason = ""
				if t.Guard != nil {
					t.Guard.SetLateralGate(false, true)
				}
				if t.TargetGuard != nil {
					t.TargetGuard.SetLateralGate(false, true)
				}
				if _, err := s.applyTaskControl(t, "resume"); err != nil {
					log.Printf("[lateral] auto-resume standby task #%s after foothold #%d failed: %v", t.ID, e.NodeID, err)
				} else {
					log.Printf("[lateral] auto-resumed standby task #%s on foothold finding #%d (%s)", t.ID, e.NodeID, e.VulnClass)
				}
			} else {
				reason := fmt.Sprintf("foothold_ready: finding #%d [%s/%s] on task #%d; awaiting approval", e.NodeID, e.Severity, e.VulnClass, e.TaskID)
				_ = s.m.pg.SetTaskParkedReason(tid, reason)
				t.ParkedReason = reason
				log.Printf("[lateral] standby task #%s foothold ready (awaiting approval): %s", t.ID, reason)
			}
			continue
		}

		// Case 2: single-task lateral gate — pause task when qualifying foothold lands
		// before lateral utilization is approved, avoiding wasted exploration turns.
		if t.ID == strconv.FormatInt(e.TaskID, 10) && t.LateralGate && !t.LateralApproved && !lifecycle.Paused {
			if !MatchesFootholdFinding(e, t.FootholdVulnClasses) {
				continue
			}
			reason := fmt.Sprintf("foothold_ready: finding #%d [%s/%s]; awaiting lateral approval", e.NodeID, e.Severity, e.VulnClass)
			tid, _ := strconv.ParseInt(t.ID, 10, 64)
			_ = s.m.pg.SetTaskParkedReason(tid, reason)
			t.ParkedReason = reason
			if _, err := s.applyTaskControl(t, "pause"); err != nil {
				log.Printf("[lateral] pause task #%s on foothold #%d failed: %v", t.ID, e.NodeID, err)
			} else {
				log.Printf("[lateral] paused task #%s on foothold #%d (%s) awaiting approval", t.ID, e.NodeID, e.VulnClass)
			}
		}
	}
}

func (s *Server) injectFootholdHint(t *Task, e db.TaskEvent) {
	if t == nil || t.Store == nil {
		return
	}
	msg := fmt.Sprintf("Foothold confirmed on upstream task #%d (finding node #%d, severity=%s, class=%s): %s",
		e.TaskID, e.NodeID, e.Severity, e.VulnClass, e.Summary)
	_, _ = t.Store.AddNode(db.KindHint, map[string]any{
		"summary": msg,
		"source":  "foothold",
	}, 100, "active", "system", nil)
}

// approveTaskLateral approves lateral movement for a gated/parked task and resumes
// it in-place without resetting exploration state.
func (s *Server) approveTaskLateral(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	var req struct {
		Note string `json:"note"`
	}
	if r.Body != nil {
		_ = decode(r, &req)
	}
	taskID, _ := strconv.ParseInt(t.ID, 10, 64)
	if err := s.m.PG().SetTaskLateralState(taskID, true, ""); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	t.LateralApproved = true
	t.ParkedReason = ""
	if t.Guard != nil {
		t.Guard.SetLateralGate(t.LateralGate, true)
	}
	if t.TargetGuard != nil {
		t.TargetGuard.SetLateralGate(t.LateralGate, true)
	}
	if note := strings.TrimSpace(req.Note); note != "" && t.Store != nil {
		_, _ = t.Store.AddNode(db.KindHint, map[string]any{
			"summary": "Lateral approval note from " + s.approver(r) + ": " + note,
			"source":  "human",
		}, 100, "active", "human", nil)
	}

	lifecycle := t.lifecycleSnapshot()
	var ctrlRes *taskControlResult
	if lifecycle.Paused && !isTerminalStatus(lifecycle.Status) {
		res, err := s.applyTaskControl(t, "resume")
		if err != nil {
			writeErr(w, 409, err.Error())
			return
		}
		ctrlRes = &res
	}
	writeJSON(w, 200, map[string]any{
		"ok":               true,
		"task_id":          t.ID,
		"lateral_approved": true,
		"control":          ctrlRes,
		"approved_by":      s.approver(r),
	})
}
