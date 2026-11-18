package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/Autumn-27/artex/traffic"
)

func (s *Server) getTaskProxyHeaders(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	if s.m == nil || s.m.traffic == nil {
		writeJSON(w, 200, map[string]any{"rules": []traffic.HostHeaderRule{}})
		return
	}
	rules := s.m.traffic.ListTaskHostHeaderRules(t.ID)
	if rules == nil {
		rules = []traffic.HostHeaderRule{}
	}
	// Mask header values when returning via API so credentials aren't echoed back in plaintext.
	masked := make([]traffic.HostHeaderRule, 0, len(rules))
	for _, rule := range rules {
		mh := make(map[string]string, len(rule.Headers))
		for k, v := range rule.Headers {
			if len(v) > 8 {
				mh[k] = v[:4] + "****" + v[len(v)-2:]
			} else {
				mh[k] = "****"
			}
		}
		masked = append(masked, traffic.HostHeaderRule{
			TaskID:    rule.TaskID,
			Host:      rule.Host,
			Headers:   mh,
			Overwrite: rule.Overwrite,
		})
	}
	writeJSON(w, 200, map[string]any{"rules": masked})
}

func (s *Server) updateTaskProxyHeaders(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	if s.m == nil || s.m.traffic == nil {
		writeErr(w, 503, "traffic proxy unavailable")
		return
	}
	var req struct {
		Rules []traffic.HostHeaderRule `json:"rules"`
	}
	if err := decode(w, r, &req); err != nil {
		writeErr(w, 400, "invalid JSON")
		return
	}
	validated := make([]traffic.HostHeaderRule, 0, len(req.Rules))
	for _, rule := range req.Rules {
		host := strings.ToLower(strings.TrimSpace(rule.Host))
		if host == "" || strings.Contains(host, "*") {
			writeErr(w, 400, fmt.Sprintf("invalid host %q (wildcards are forbidden to prevent credential leakage)", rule.Host))
			return
		}
		if t.FenceEnabled && t.Guard != nil {
			checkHost := strings.TrimPrefix(host, ".")
			probe, _ := json.Marshal(map[string]string{"url": "https://" + checkHost + "/"})
			if blocked, reason := t.Guard.CheckFence("WebFetch", probe); blocked {
				writeErr(w, 403, fmt.Sprintf("electronic fence rejected proxy header host %q: %s", host, reason))
				return
			}
		}
		if len(rule.Headers) == 0 {
			continue
		}
		validated = append(validated, traffic.HostHeaderRule{
			TaskID:    t.ID,
			Host:      host,
			Headers:   rule.Headers,
			Overwrite: rule.Overwrite,
		})
	}
	s.m.traffic.SetTaskHostHeaderRules(t.ID, validated)
	writeJSON(w, 200, map[string]any{"updated": true, "rule_count": len(validated)})
}
