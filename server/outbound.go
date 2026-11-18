package server

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
)

func isLoopbackHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" || h == "localhost" {
		return true
	}
	if addr, err := netip.ParseAddr(h); err == nil {
		return addr.IsLoopback()
	}
	return false
}

func isPrivateIPHost(host string) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(host))
	if err != nil {
		return false
	}
	return addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsLoopback()
}

func extractHostPort(raw string) (string, int) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", 0
	}
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil {
			port := 0
			if p := u.Port(); p != "" {
				port, _ = strconv.Atoi(p)
			} else if strings.EqualFold(u.Scheme, "https") {
				port = 443
			} else if strings.EqualFold(u.Scheme, "http") {
				port = 80
			}
			return strings.ToLower(u.Hostname()), port
		}
	}
	if h, p, err := netSplitHostPortSafe(s); err == nil {
		port, _ := strconv.Atoi(p)
		return strings.ToLower(h), port
	}
	return strings.ToLower(s), 0
}

func netSplitHostPortSafe(s string) (string, string, error) {
	idx := strings.LastIndex(s, ":")
	if idx <= 0 || strings.Contains(s[idx+1:], "]") {
		return "", "", strconv.ErrSyntax
	}
	return strings.Trim(s[:idx], "[]"), s[idx+1:], nil
}

func matchesDeclaredTargets(targets []string, host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" {
		return false
	}
	for _, tgt := range targets {
		th, _ := extractHostPort(tgt)
		if th == "" {
			continue
		}
		if th == h || strings.HasSuffix(h, "."+th) {
			return true
		}
		if pfx, err := netip.ParsePrefix(strings.TrimSpace(tgt)); err == nil {
			if addr, err := netip.ParseAddr(h); err == nil && pfx.Contains(addr) {
				return true
			}
		}
	}
	return false
}

func shouldRecordOutbound(t *Task, host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" || isLoopbackHost(h) {
		return false
	}
	if t != nil && matchesDeclaredTargets(t.FenceRules, h) {
		return false
	}
	if isPrivateIPHost(h) {
		return false
	}
	if t != nil && t.FenceEnabled && t.Guard != nil {
		probe, _ := json.Marshal(map[string]string{"url": "https://" + h + "/"})
		if blocked, _ := t.Guard.CheckFence("WebFetch", probe); !blocked {
			// Host is inside explicit fence rules; if it's an internal domain (no dot or .local/.corp/.internal),
			// treat as internal target; public domains still get audited unless explicitly matched.
			if !strings.Contains(h, ".") || strings.HasSuffix(h, ".local") || strings.HasSuffix(h, ".internal") || strings.HasSuffix(h, ".corp") {
				return false
			}
		}
	}
	return true
}

func (s *Server) recordTaskOutbound(t *Task, source, protocol, targetRaw, method, purpose string) {
	if s == nil || s.m == nil || s.m.pg == nil || t == nil {
		return
	}
	host, port := extractHostPort(targetRaw)
	if !shouldRecordOutbound(t, host) {
		return
	}
	tid, err := strconv.ParseInt(t.ID, 10, 64)
	if err != nil || tid <= 0 {
		return
	}
	go func() {
		_ = s.m.pg.RecordOutboundLog(db.RecordOutboundInput{
			TaskID:     tid,
			Source:     source,
			Protocol:   protocol,
			TargetHost: host,
			TargetPort: port,
			Method:     method,
			URLPreview: targetRaw,
			Purpose:    purpose,
		})
	}()
}

func (s *Server) recordProxyOutbound(host string, port int, scheme, method, rawURL string) {
	if s == nil || s.m == nil || s.m.pg == nil {
		return
	}
	tasks := s.m.List()
	for _, t := range tasks {
		if t == nil || t.CompletedAt != 0 || t.Paused || t.Queued {
			continue
		}
		if !shouldRecordOutbound(t, host) {
			continue
		}
		tid, err := strconv.ParseInt(t.ID, 10, 64)
		if err != nil || tid <= 0 {
			continue
		}
		_ = s.m.pg.RecordOutboundLog(db.RecordOutboundInput{
			TaskID:     tid,
			Source:     "proxy",
			Protocol:   scheme,
			TargetHost: host,
			TargetPort: port,
			Method:     method,
			URLPreview: rawURL,
			Purpose:    "HTTP/HTTPS proxy egress",
		})
	}
}

// GET /api/tasks/{id}/outbound — returns recorded external outbound connections for a task.
func (s *Server) listTaskOutbound(w http.ResponseWriter, r *http.Request) {
	if s.m == nil || s.m.pg == nil {
		writeJSON(w, 200, map[string]any{"outbound": []db.OutboundLog{}})
		return
	}
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	tid, err := strconv.ParseInt(t.ID, 10, 64)
	if err != nil || tid <= 0 {
		writeErr(w, 400, "invalid task id")
		return
	}
	logs, err := s.m.pg.ListTaskOutboundLogs(tid)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if logs == nil {
		logs = []db.OutboundLog{}
	}
	writeJSON(w, 200, map[string]any{"outbound": logs})
}
