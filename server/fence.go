package server

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/guard"
)

func validateFenceInput(enabledPtr *bool, rawRules []string) (enabled bool, norm []string, err error) {
	seen := map[string]bool{}
	for _, raw := range rawRules {
		s := strings.TrimSpace(raw)
		if s == "" || seen[strings.ToLower(s)] {
			continue
		}
		seen[strings.ToLower(s)] = true
		norm = append(norm, s)
	}
	if norm == nil {
		norm = []string{}
	}
	if _, err := guard.ParseFenceRules(norm); err != nil {
		return false, nil, err
	}
	enabled = len(norm) > 0
	if enabledPtr != nil {
		enabled = *enabledPtr
	}
	if enabled && len(norm) == 0 {
		return false, nil, fmt.Errorf("fence_rules cannot be empty when fence_enabled is true")
	}
	return enabled, norm, nil
}

func (s *Server) applyTaskFenceConstraint(t *Task) {
	if t == nil || !t.FenceEnabled || t.Store == nil || len(t.FenceRules) == 0 {
		return
	}
	_, _ = t.Store.AddConstraint("deny",
		"【电子围栏硬边界】本任务已启用测试电子围栏，仅允许探测或访问以下授权目标，严禁向围栏外任何 IP/网段/域名发起请求或横向蔓延："+strings.Join(t.FenceRules, ", "),
		"system")
}

func (s *Server) getTaskFence(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	t.lifecycleMu.RLock()
	enabled := t.FenceEnabled
	rules := append([]string(nil), t.FenceRules...)
	t.lifecycleMu.RUnlock()
	if rules == nil {
		rules = []string{}
	}
	writeJSON(w, 200, map[string]any{
		"task_id":       t.ID,
		"fence_enabled": enabled,
		"fence_rules":   rules,
	})
}

func (s *Server) updateTaskFence(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	var req struct {
		FenceEnabled *bool    `json:"fence_enabled"`
		FenceRules   []string `json:"fence_rules"`
	}
	if err := decode(w, r, &req); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	enabled, norm, err := validateFenceInput(req.FenceEnabled, req.FenceRules)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	taskID, _ := strconv.ParseInt(t.ID, 10, 64)
	if err := s.m.PG().SetTaskFence(taskID, enabled, norm); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	t.lifecycleMu.Lock()
	t.FenceEnabled = enabled
	t.FenceRules = append([]string(nil), norm...)
	t.lifecycleMu.Unlock()
	s.m.applyTaskFence(t)
	s.applyTaskFenceConstraint(t)

	writeJSON(w, 200, map[string]any{
		"task_id":       t.ID,
		"fence_enabled": enabled,
		"fence_rules":   norm,
	})
}
