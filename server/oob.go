package server

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/oob"
	actool "github.com/Autumn-27/norma/tool"
)

// handleOOBCallback receives unauthenticated inbound HTTP callbacks at /oob/{token}
// and /oob/{token}/{rest...} for blind vulnerability verification (SSRF/XXE/RCE)
// in air-gapped or intranet environments.
func (s *Server) handleOOBCallback(w http.ResponseWriter, r *http.Request) {
	if s.oobMgr != nil {
		token := strings.TrimSpace(r.PathValue("token"))
		if token != "" {
			bodyBytes, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
			hdrs := map[string]string{}
			for _, k := range []string{"User-Agent", "Host", "Content-Type", "X-Forwarded-For"} {
				if v := strings.TrimSpace(r.Header.Get(k)); v != "" {
					hdrs[k] = v
				}
			}
			s.oobMgr.RecordHit(token, oob.Hit{
				RemoteIP: clientIP(r, s.trustedProxies),
				Method:   r.Method,
				Path:     r.URL.Path,
				Query:    r.URL.RawQuery,
				Headers:  hdrs,
				Body:     string(bodyBytes),
			})
		}
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func (s *Server) listTaskOOBTokens(w http.ResponseWriter, r *http.Request) {
	if s.oobMgr == nil {
		writeJSON(w, 200, map[string]any{"tokens": []oob.Token{}})
		return
	}
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	tid, err := strconv.ParseInt(t.ID, 10, 64)
	if err != nil {
		writeErr(w, 400, "invalid task id")
		return
	}
	writeJSON(w, 200, map[string]any{"tokens": s.oobMgr.ListTaskTokens(tid)})
}

func (s *Server) oobTools() []actool.CoreTool {
	return []actool.CoreTool{
		s.toolOOBCreateToken(),
		s.toolOOBPollHits(),
	}
}

func (s *Server) seedOOBTools() {
	if s.m == nil || s.m.pg == nil {
		return
	}
	agents, _ := json.Marshal([]string{"worker", "planner", "main", "auto", "pentest"})
	for _, t := range s.oobTools() {
		schema, _ := json.Marshal(t.InputSchema())
		if err := s.m.pg.SeedTool(t.Name(), t.Description(), schema, agents); err != nil {
			log.Printf("[oob] seed tool %s: %v", t.Name(), err)
		}
	}
}

func oobBaseURL() string {
	if v := strings.TrimRight(strings.TrimSpace(os.Getenv("ARTEX_OOB_BASE_URL")), "/"); v != "" {
		return v
	}
	return "http://127.0.0.1:8787"
}

func (s *Server) toolOOBCreateToken() actool.CoreTool {
	return wrTool(
		"oob_create_token",
		"Allocate a task-scoped internal OOB HTTP callback token (/oob/<token>) for verifying blind vulnerabilities (Blind SSRF, XXE, RCE, Log4j/Fastjson) in air-gapped or intranet environments without public interactsh.",
		objSchema(map[string]any{
			"task_id": strParam("Task ID (numeric string)"),
			"label":   strParam("Short human-readable label (e.g. 'ssrf-avatar-upload')"),
		}, "task_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if s.oobMgr == nil {
				return actool.Errorf("OOB tracker unavailable"), nil
			}
			var p struct {
				TaskID string `json:"task_id"`
				Label  string `json:"label"`
			}
			if err := json.Unmarshal(in, &p); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			t, ok := s.m.Task(p.TaskID)
			if !ok {
				return actool.Errorf("task not found"), nil
			}
			tid, err := strconv.ParseInt(t.ID, 10, 64)
			if err != nil {
				return actool.Errorf("invalid task id"), nil
			}
			tok, err := s.oobMgr.CreateToken(tid, strings.TrimSpace(p.Label))
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			base := oobBaseURL()
			path := "/oob/" + tok.ID
			return jsonResult(map[string]any{
				"token":         tok.ID,
				"label":         tok.Label,
				"callback_path": path,
				"callback_url":  base + path,
				"note":          "If ARTEX_OOB_BASE_URL is not set, replace 127.0.0.1:8787 with ARTEX's intranet-reachable IP:port for remote target callbacks.",
			})
		},
	)
}

func (s *Server) toolOOBPollHits() actool.CoreTool {
	return roTool(
		"oob_poll_hits",
		"Poll recorded inbound HTTP callback hits for a task-scoped OOB token to confirm blind vulnerability execution.",
		objSchema(map[string]any{
			"task_id":      strParam("Task ID (numeric string)"),
			"token":        strParam("OOB token returned by oob_create_token"),
			"wait_seconds": map[string]any{"type": "integer", "description": "Optional wait up to 10 seconds if no hits have arrived yet"},
		}, "task_id", "token"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if s.oobMgr == nil {
				return actool.Errorf("OOB tracker unavailable"), nil
			}
			var p struct {
				TaskID      string `json:"task_id"`
				Token       string `json:"token"`
				WaitSeconds int    `json:"wait_seconds"`
			}
			if err := json.Unmarshal(in, &p); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			t, ok := s.m.Task(p.TaskID)
			if !ok {
				return actool.Errorf("task not found"), nil
			}
			tid, err := strconv.ParseInt(t.ID, 10, 64)
			if err != nil {
				return actool.Errorf("invalid task id"), nil
			}
			if p.WaitSeconds < 0 {
				p.WaitSeconds = 0
			}
			if p.WaitSeconds > 10 {
				p.WaitSeconds = 10
			}
			deadline := time.Now().Add(time.Duration(p.WaitSeconds) * time.Second)
			for {
				tok, hits, found := s.oobMgr.PollHits(tid, strings.TrimSpace(p.Token))
				if !found {
					return actool.Errorf("oob token not found for task"), nil
				}
				if len(hits) > 0 || time.Now().After(deadline) {
					return jsonResult(map[string]any{
						"token":     tok.ID,
						"label":     tok.Label,
						"hit_count": tok.HitCount,
						"hits":      hits,
					})
				}
				select {
				case <-ctx.Done():
					return jsonResult(map[string]any{
						"token":     tok.ID,
						"label":     tok.Label,
						"hit_count": tok.HitCount,
						"hits":      hits,
					})
				case <-time.After(200 * time.Millisecond):
				}
			}
		},
	)
}
