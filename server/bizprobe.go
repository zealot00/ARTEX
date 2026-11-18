package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	actool "github.com/Autumn-27/norma/tool"
)

const (
	maxBizRespBytes    = 64 * 1024
	maxRaceConcurrency = 20
	prodSafeRaceCap    = 5
)

func (s *Server) bizProbeTools() []actool.CoreTool {
	return []actool.CoreTool{
		s.toolAuthzReplay(),
		s.toolRaceProbe(),
	}
}

func (s *Server) seedBizProbeTools() {
	if s.m == nil || s.m.pg == nil {
		return
	}
	agents, _ := json.Marshal([]string{"worker", "planner", "main", "auto", "pentest"})
	for _, t := range s.bizProbeTools() {
		schema, _ := json.Marshal(t.InputSchema())
		if err := s.m.pg.SeedTool(t.Name(), t.Description(), schema, agents); err != nil {
			log.Printf("[bizprobe] seed tool %s: %v", t.Name(), err)
		}
	}
}

func safeHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		// Never follow redirects automatically so targets cannot bounce out of the electronic fence.
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func execBoundedHTTP(ctx context.Context, client *http.Client, method, rawURL string, headers map[string]string, body string) (status int, length int, hash string, preview string, err error) {
	var bodyReader io.Reader
	if body != "" {
		bodyReader = bytes.NewBufferString(body)
	}
	req, err := http.NewRequestWithContext(ctx, strings.ToUpper(strings.TrimSpace(method)), rawURL, bodyReader)
	if err != nil {
		return 0, 0, "", "", err
	}
	for k, v := range headers {
		if strings.TrimSpace(k) != "" {
			req.Header.Set(k, v)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, 0, "", "", err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBizRespBytes))
	if err != nil {
		return resp.StatusCode, 0, "", "", err
	}
	sum := sha256.Sum256(data)
	p := strings.TrimSpace(string(data))
	if len(p) > 300 {
		p = p[:300] + "..."
	}
	return resp.StatusCode, len(data), hex.EncodeToString(sum[:8]), p, nil
}

func stripAuthHeaders(h map[string]string) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		lk := strings.ToLower(strings.TrimSpace(k))
		if lk == "authorization" || lk == "cookie" || lk == "x-token" || lk == "x-auth-token" || lk == "x-api-key" {
			continue
		}
		out[k] = v
	}
	return out
}

func cloneHeadersWithOverride(base, override map[string]string) map[string]string {
	out := make(map[string]string, len(base)+len(override))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range override {
		out[k] = v
	}
	return out
}

func (s *Server) toolAuthzReplay() actool.CoreTool {
	return wrTool(
		"authz_replay",
		"Automated multi-role authorization & IDOR comparison tool (like Burp Autorize). Replays a target HTTP request across baseline (high-priv), unauthenticated (auth headers stripped), optional low-priv credentials, and optional path/method bypasses, enforcing electronic fence and strict non-redirect bounds.",
		objSchema(map[string]any{
			"task_id":          strParam("Task ID (numeric string)"),
			"url":              strParam("Full target URL (must pass electronic fence)"),
			"method":           strParam("HTTP method (default GET)"),
			"headers":          map[string]any{"type": "object", "description": "Baseline authenticated request headers (e.g. Cookie, Authorization)"},
			"body":             strParam("Optional request body"),
			"low_priv_headers": map[string]any{"type": "object", "description": "Optional secondary/low-privilege account headers to test horizontal/vertical escalation"},
			"include_bypasses": map[string]any{"type": "boolean", "description": "Also test path normalization (..;/) and X-Forwarded-For / X-Original-URL bypasses"},
		}, "task_id", "url"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var p struct {
				TaskID          string            `json:"task_id"`
				URL             string            `json:"url"`
				Method          string            `json:"method"`
				Headers         map[string]string `json:"headers"`
				Body            string            `json:"body"`
				LowPrivHeaders  map[string]string `json:"low_priv_headers"`
				IncludeBypasses bool              `json:"include_bypasses"`
			}
			if err := json.Unmarshal(in, &p); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			p.URL = strings.TrimSpace(p.URL)
			if p.URL == "" {
				return actool.Errorf("url is required"), nil
			}
			if p.Method == "" {
				p.Method = "GET"
			}
			u, err := url.Parse(p.URL)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
				return actool.Errorf("invalid http/https url"), nil
			}

			t := s.m.ResolveTask(strings.TrimSpace(p.TaskID))
			if t == nil {
				return actool.Errorf("task not found"), nil
			}
			if t.Guard != nil {
				probe, _ := json.Marshal(map[string]string{"url": p.URL})
				if blocked, reason := t.Guard.CheckFence("WebFetch", probe); blocked {
					return actool.Errorf(fmt.Sprintf("electronic fence blocked authz_replay: %s", reason)), nil
				}
			}
			s.recordTaskOutbound(t, "authz_replay", u.Scheme, p.URL, p.Method, "Authorization replay check")

			client := safeHTTPClient(10 * time.Second)
			type probeVariant struct {
				name    string
				method  string
				url     string
				headers map[string]string
			}
			variants := []probeVariant{
				{name: "baseline", method: p.Method, url: p.URL, headers: p.Headers},
				{name: "unauthenticated", method: p.Method, url: p.URL, headers: stripAuthHeaders(p.Headers)},
			}
			if len(p.LowPrivHeaders) > 0 {
				merged := cloneHeadersWithOverride(stripAuthHeaders(p.Headers), p.LowPrivHeaders)
				variants = append(variants, probeVariant{name: "low_priv", method: p.Method, url: p.URL, headers: merged})
			}
			if p.IncludeBypasses {
				origin := u.Scheme + "://" + u.Host
				pathPart := u.EscapedPath()
				if pathPart == "" {
					pathPart = "/"
				}
				variants = append(variants,
					probeVariant{name: "bypass_dot_semicolon", method: p.Method, url: origin + "/..;" + pathPart, headers: stripAuthHeaders(p.Headers)},
					probeVariant{name: "bypass_xff_loopback", method: p.Method, url: p.URL, headers: cloneHeadersWithOverride(stripAuthHeaders(p.Headers), map[string]string{"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1"})},
					probeVariant{name: "bypass_x_original_url", method: p.Method, url: origin + "/", headers: cloneHeadersWithOverride(stripAuthHeaders(p.Headers), map[string]string{"X-Original-URL": pathPart})},
				)
			}

			type variantResult struct {
				Variant       string `json:"variant"`
				Status        int    `json:"status"`
				Length        int    `json:"length"`
				BodyHash      string `json:"body_hash,omitempty"`
				MatchesBase   bool   `json:"matches_baseline_body"`
				Preview       string `json:"preview,omitempty"`
				Error         string `json:"error,omitempty"`
				SuspectBypass bool   `json:"suspect_bypass"`
			}

			results := make([]variantResult, 0, len(variants))
			var baseStatus int
			var baseHash string
			for i, v := range variants {
				st, ln, h, prev, reqErr := execBoundedHTTP(ctx, client, v.method, v.url, v.headers, p.Body)
				vr := variantResult{Variant: v.name, Status: st, Length: ln, BodyHash: h, Preview: prev}
				if reqErr != nil {
					vr.Error = reqErr.Error()
				} else if i == 0 {
					baseStatus = st
					baseHash = h
				} else {
					vr.MatchesBase = (h != "" && h == baseHash)
					if baseStatus >= 200 && baseStatus < 300 && st >= 200 && st < 300 && (vr.MatchesBase || ln > 0) {
						vr.SuspectBypass = true
					}
				}
				results = append(results, vr)
			}

			return jsonResult(map[string]any{
				"url":     p.URL,
				"method":  p.Method,
				"results": results,
			})
		},
	)
}

func (s *Server) toolRaceProbe() actool.CoreTool {
	return wrTool(
		"race_probe",
		"Synchronized barrier concurrent HTTP probe for testing race conditions (approval/quota/coupon/state-machine races). Releases N goroutines simultaneously under electronic fence and prod_safe_mode concurrency caps.",
		objSchema(map[string]any{
			"task_id":     strParam("Task ID (numeric string)"),
			"url":         strParam("Full target URL (must pass electronic fence)"),
			"method":      strParam("HTTP method (default POST)"),
			"headers":     map[string]any{"type": "object", "description": "Optional request headers"},
			"body":        strParam("Optional request body"),
			"concurrency": map[string]any{"type": "integer", "description": "Simultaneous requests (default 8, max 20; capped at 5 in prod_safe_mode)"},
		}, "task_id", "url"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var p struct {
				TaskID      string            `json:"task_id"`
				URL         string            `json:"url"`
				Method      string            `json:"method"`
				Headers     map[string]string `json:"headers"`
				Body        string            `json:"body"`
				Concurrency int               `json:"concurrency"`
			}
			if err := json.Unmarshal(in, &p); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			p.URL = strings.TrimSpace(p.URL)
			if p.URL == "" {
				return actool.Errorf("url is required"), nil
			}
			if p.Method == "" {
				p.Method = "POST"
			}
			u, err := url.Parse(p.URL)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
				return actool.Errorf("invalid http/https url"), nil
			}

			t := s.m.ResolveTask(strings.TrimSpace(p.TaskID))
			if t == nil {
				return actool.Errorf("task not found"), nil
			}
			if t.Guard != nil {
				probe, _ := json.Marshal(map[string]string{"url": p.URL})
				if blocked, reason := t.Guard.CheckFence("WebFetch", probe); blocked {
					return actool.Errorf(fmt.Sprintf("electronic fence blocked race_probe: %s", reason)), nil
				}
			}

			n := p.Concurrency
			if n <= 0 {
				n = 8
			}
			capLimit := maxRaceConcurrency
			if t.ProdSafeMode {
				capLimit = prodSafeRaceCap
			}
			if n > capLimit {
				n = capLimit
			}
			s.recordTaskOutbound(t, "race_probe", u.Scheme, p.URL, p.Method, "Race condition probe")

			client := safeHTTPClient(10 * time.Second)
			startGate := make(chan struct{})
			var wg sync.WaitGroup
			var mu sync.Mutex
			statusCounts := map[int]int{}
			hashCounts := map[string]int{}
			errCount := 0

			for i := 0; i < n; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-startGate
					st, _, h, _, reqErr := execBoundedHTTP(ctx, client, p.Method, p.URL, p.Headers, p.Body)
					mu.Lock()
					defer mu.Unlock()
					if reqErr != nil {
						errCount++
						return
					}
					statusCounts[st]++
					if h != "" {
						hashCounts[h]++
					}
				}()
			}
			started := time.Now()
			close(startGate)
			wg.Wait()
			elapsedMs := time.Since(started).Milliseconds()

			return jsonResult(map[string]any{
				"url":                 p.URL,
				"method":              p.Method,
				"concurrency_used":    n,
				"prod_safe_capped":    t.ProdSafeMode,
				"elapsed_ms":          elapsedMs,
				"status_distribution": statusCounts,
				"unique_body_hashes":  hashCounts,
				"error_count":         errCount,
			})
		},
	)
}
