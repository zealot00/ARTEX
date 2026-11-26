package server

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/textclean"
	actool "github.com/Autumn-27/norma/tool"
)

const maxContractBytes = 512 * 1024

var (
	reScriptSrc = regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+\.js(?:\?[^"']*)?)["']`)
	reAPIPath   = regexp.MustCompile(`["']((?:/api/|/v1/|/v2/|/v3/|/admin/|/internal/|/graphql|/actuator/)[A-Za-z0-9_\-./{}]+)(?:\?[^"']*)?["']`)
	reQueryKey  = regexp.MustCompile(`[?&]([a-zA-Z_][a-zA-Z0-9_]{1,31})=`)
)

// DiscoveredContractEndpoint represents an API endpoint extracted from OpenAPI/Swagger or JS bundles.
type DiscoveredContractEndpoint struct {
	Method string           `json:"method"`
	Path   string           `json:"path"`
	URL    string           `json:"url"`
	Source string           `json:"source"`
	Params []map[string]any `json:"params,omitempty"`
	Tags   []string         `json:"tags,omitempty"`
}

// ParseOpenAPIEndpoints parses Swagger 2.0 or OpenAPI 3.x JSON documents into normalized endpoints.
func ParseOpenAPIEndpoints(baseURL string, raw []byte) []DiscoveredContractEndpoint {
	var doc struct {
		Paths map[string]map[string]struct {
			Parameters []struct {
				Name string `json:"name"`
				In   string `json:"in"`
			} `json:"parameters"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil || len(doc.Paths) == 0 {
		return nil
	}
	base := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	var out []DiscoveredContractEndpoint
	for p, methods := range doc.Paths {
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		for m, op := range methods {
			up := strings.ToUpper(strings.TrimSpace(m))
			switch up {
			case "GET", "POST", "PUT", "DELETE", "PATCH":
			default:
				continue
			}
			var params []map[string]any
			for _, prm := range op.Parameters {
				if strings.TrimSpace(prm.Name) == "" {
					continue
				}
				loc := strings.ToLower(strings.TrimSpace(prm.In))
				if loc == "" {
					loc = "query"
				}
				params = append(params, map[string]any{
					"name":     prm.Name,
					"location": loc,
				})
			}
			fullURL := base + p
			out = append(out, DiscoveredContractEndpoint{
				Method: up,
				Path:   p,
				URL:    fullURL,
				Source: "openapi",
				Params: params,
				Tags:   ClassifyEndpointParamTags(params, fullURL),
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Method < out[j].Method
	})
	return out
}

// ParseJSBundleEndpoints extracts API routes and query parameter names from HTML/JS text.
func ParseJSBundleEndpoints(baseURL, sourceLabel, text string) []DiscoveredContractEndpoint {
	base := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	matches := reAPIPath.FindAllStringSubmatch(text, 200)
	if len(matches) == 0 {
		return nil
	}
	var commonParams []map[string]any
	seenParam := map[string]bool{}
	for _, qm := range reQueryKey.FindAllStringSubmatch(text, 50) {
		k := qm[1]
		if !seenParam[k] {
			seenParam[k] = true
			commonParams = append(commonParams, map[string]any{
				"name":     k,
				"location": "query",
			})
		}
	}
	seenPath := map[string]bool{}
	var out []DiscoveredContractEndpoint
	for _, m := range matches {
		p := strings.TrimSpace(m[1])
		if p == "" || seenPath[p] {
			continue
		}
		seenPath[p] = true
		fullURL := base + p
		out = append(out, DiscoveredContractEndpoint{
			Method: "GET",
			Path:   p,
			URL:    fullURL,
			Source: sourceLabel,
			Params: commonParams,
			Tags:   ClassifyEndpointParamTags(commonParams, fullURL),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

func (s *Server) toolExtractWebContracts() actool.CoreTool {
	return wrTool(
		"extract_web_contracts",
		"Automated API & front-end contract discovery tool: inspects an in-scope web service for OpenAPI/Swagger specifications (/v3/api-docs, /v2/api-docs, /swagger.json, /openapi.json) and referenced JavaScript bundles, extracts API routes and parameter schemas, tags them by security review category, and registers discovered endpoints into the task's asset graph.",
		objSchema(map[string]any{
			"task_id":         strParam("Task ID (numeric string)"),
			"base_url":        strParam("Authorized target base URL (e.g. 'http://10.10.1.5:8080')"),
			"register_assets": map[string]any{"type": "boolean", "description": "Automatically register discovered endpoints into the task asset inventory (default true)"},
		}, "task_id", "base_url"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var p struct {
				TaskID         string `json:"task_id"`
				BaseURL        string `json:"base_url"`
				RegisterAssets *bool  `json:"register_assets"`
			}
			if err := json.Unmarshal(in, &p); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			p.BaseURL = strings.TrimRight(strings.TrimSpace(p.BaseURL), "/")
			u, err := url.Parse(p.BaseURL)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
				return actool.Errorf("invalid http/https base_url"), nil
			}
			t := s.m.ResolveTask(strings.TrimSpace(p.TaskID))
			if t == nil {
				return actool.Errorf("task not found"), nil
			}
			if t.Guard != nil {
				probe, _ := json.Marshal(map[string]string{"url": p.BaseURL})
				if blocked, reason := t.Guard.CheckFence("WebFetch", probe); blocked {
					return actool.Errorf(fmt.Sprintf("electronic fence blocked extract_web_contracts: %s", reason)), nil
				}
			}
			s.recordTaskOutbound(t, "extract_web_contracts", u.Scheme, p.BaseURL, "GET", "OpenAPI and JS contract discovery")

			client := safeHTTPClient(8 * time.Second)
			var discovered []DiscoveredContractEndpoint
			seenKey := map[string]bool{}
			addEndpoint := func(ep DiscoveredContractEndpoint) {
				k := ep.Method + " " + ep.Path
				if !seenKey[k] && len(discovered) < 120 {
					seenKey[k] = true
					discovered = append(discovered, ep)
				}
			}

			// 1. Check standard OpenAPI / Swagger endpoints.
			for _, specPath := range []string{"/v3/api-docs", "/v2/api-docs", "/openapi.json", "/swagger.json", "/api/swagger.json"} {
				specURL := p.BaseURL + specPath
				req, reqErr := http.NewRequestWithContext(ctx, "GET", specURL, nil)
				if reqErr != nil {
					continue
				}
				resp, doErr := client.Do(req)
				if doErr != nil {
					continue
				}
				body, _ := io.ReadAll(io.LimitReader(resp.Body, maxContractBytes))
				resp.Body.Close()
				if resp.StatusCode == 200 && len(body) > 0 {
					for _, ep := range ParseOpenAPIEndpoints(p.BaseURL, body) {
						addEndpoint(ep)
					}
				}
			}

			// 2. Inspect homepage HTML and up to 5 same-origin JS bundles.
			var scriptURLs []string
			if req, reqErr := http.NewRequestWithContext(ctx, "GET", p.BaseURL+"/", nil); reqErr == nil {
				if resp, doErr := client.Do(req); doErr == nil {
					body, _ := io.ReadAll(io.LimitReader(resp.Body, maxContractBytes))
					resp.Body.Close()
					htmlText := string(body)
					for _, ep := range ParseJSBundleEndpoints(p.BaseURL, "html", htmlText) {
						addEndpoint(ep)
					}
					for _, sm := range reScriptSrc.FindAllStringSubmatch(htmlText, 10) {
						ref, parseErr := u.Parse(sm[1])
						if parseErr == nil && strings.EqualFold(ref.Host, u.Host) {
							scriptURLs = append(scriptURLs, ref.String())
							if len(scriptURLs) >= 5 {
								break
							}
						}
					}
				}
			}

			for _, jsURL := range scriptURLs {
				req, reqErr := http.NewRequestWithContext(ctx, "GET", jsURL, nil)
				if reqErr != nil {
					continue
				}
				resp, doErr := client.Do(req)
				if doErr != nil {
					continue
				}
				body, _ := io.ReadAll(io.LimitReader(resp.Body, maxContractBytes))
				resp.Body.Close()
				if resp.StatusCode == 200 && len(body) > 0 {
					decodedBody := textclean.CleanBytes(body, resp.Header.Get("Content-Type"), resp.Header.Get("Content-Encoding"))
					for _, ep := range ParseJSBundleEndpoints(p.BaseURL, "js_bundle", decodedBody) {
						addEndpoint(ep)
					}
				}
			}

			register := p.RegisterAssets == nil || *p.RegisterAssets
			registeredCount := 0
			tid, _ := strconv.ParseInt(t.ID, 10, 64)
			if register && s.m != nil && s.m.assets != nil && tid > 0 {
				for _, ep := range discovered {
					if _, upErr := s.m.assets.UpsertEndpoint(db.UpsertEndpointReq{
						URL:    ep.URL,
						Method: ep.Method,
						Params: ep.Params,
						TaskID: tid,
					}); upErr == nil {
						registeredCount++
					}
				}
			}

			if discovered == nil {
				discovered = []DiscoveredContractEndpoint{}
			}
			return jsonResult(map[string]any{
				"base_url":              p.BaseURL,
				"discovered_count":      len(discovered),
				"registered_into_graph": registeredCount,
				"endpoints":             discovered,
			})
		},
	)
}

// parseCapturedRawRequest extracts headers and body from a raw HTTP request string recorded by traffic.Get.
func parseCapturedRawRequest(rawReq string) (headers map[string]string, body string) {
	headers = map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(rawReq))
	first := true
	inHeaders := true
	var bodyLines []string
	for sc.Scan() {
		line := sc.Text()
		if first {
			first = false
			continue
		}
		if inHeaders {
			if strings.TrimSpace(line) == "" {
				inHeaders = false
				continue
			}
			if idx := strings.Index(line, ":"); idx > 0 {
				k := strings.TrimSpace(line[:idx])
				v := strings.TrimSpace(line[idx+1:])
				if !strings.EqualFold(k, "Host") && !strings.EqualFold(k, "Content-Length") {
					headers[k] = v
				}
			}
			continue
		}
		bodyLines = append(bodyLines, line)
	}
	return headers, strings.Join(bodyLines, "\n")
}

func (s *Server) toolTrafficFuzzAudit() actool.CoreTool {
	return wrTool(
		"traffic_fuzz_audit",
		"Traffic-driven API authorization and parameter audit tool: reads captured HTTP exchanges for a target host from the recording proxy, deduplicates endpoints, and replays non-destructive unauthenticated/low-privilege authorization checks plus boundary parameter type checks under electronic fence and prod_safe_mode limits.",
		objSchema(map[string]any{
			"task_id":          strParam("Task ID (numeric string)"),
			"host":             strParam("Target hostname or host:port captured in recording proxy"),
			"low_priv_headers": map[string]any{"type": "object", "description": "Optional low-privilege account headers (e.g. Cookie/Authorization) for batch cross-role verification"},
			"max_endpoints":    map[string]any{"type": "integer", "description": "Maximum captured endpoints to audit in one batch (default 6, max 12; capped at 5 in prod_safe_mode)"},
		}, "task_id", "host"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var p struct {
				TaskID         string            `json:"task_id"`
				Host           string            `json:"host"`
				LowPrivHeaders map[string]string `json:"low_priv_headers"`
				MaxEndpoints   int               `json:"max_endpoints"`
			}
			if err := json.Unmarshal(in, &p); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			p.Host = strings.TrimSpace(p.Host)
			if p.Host == "" {
				return actool.Errorf("host is required"), nil
			}
			t := s.m.ResolveTask(strings.TrimSpace(p.TaskID))
			if t == nil {
				return actool.Errorf("task not found"), nil
			}
			if s.m == nil || s.m.traffic == nil {
				return actool.Errorf("traffic recording store unavailable"), nil
			}

			t.lifecycleMu.RLock()
			prodSafe := t.ProdSafeMode
			t.lifecycleMu.RUnlock()

			limit := p.MaxEndpoints
			if limit <= 0 {
				limit = 6
			}
			capLimit := 12
			if prodSafe {
				capLimit = 5
			}
			if limit > capLimit {
				limit = capLimit
			}

			exchanges, err := s.m.traffic.Search(p.Host, 0, 50)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}

			type auditItem struct {
				ExchangeID        string   `json:"exchange_id"`
				Method            string   `json:"method"`
				URL               string   `json:"url"`
				BaselineStatus    int      `json:"baseline_status"`
				UnauthStatus      int      `json:"unauth_status"`
				LowPrivStatus     int      `json:"low_priv_status,omitempty"`
				SuspectAuthBypass bool     `json:"suspect_auth_bypass"`
				Tags              []string `json:"tags,omitempty"`
				Note              string   `json:"note,omitempty"`
			}

			client := safeHTTPClient(8 * time.Second)
			seenTemplate := map[string]bool{}
			var audited []auditItem
			suspectCount := 0

			for _, ex := range exchanges {
				if len(audited) >= limit {
					break
				}
				key := ex.Method + " " + ex.URLTemplate
				if key == " " {
					key = ex.Method + " " + ex.URL
				}
				if seenTemplate[key] {
					continue
				}
				seenTemplate[key] = true

				if t.Guard != nil {
					probe, _ := json.Marshal(map[string]string{"url": ex.URL})
					if blocked, _ := t.Guard.CheckFence("WebFetch", probe); blocked {
						continue
					}
				}

				rawReq, _, getErr := s.m.traffic.Get(ex.ID)
				if getErr != nil {
					continue
				}
				hdrs, body := parseCapturedRawRequest(rawReq)
				unauthHdrs := stripAuthHeaders(hdrs)
				hadAuth := len(unauthHdrs) < len(hdrs)

				unauthStatus, unauthLen, _, _, reqErr := execBoundedHTTP(ctx, client, ex.Method, ex.URL, unauthHdrs, body)
				if reqErr != nil {
					continue
				}

				item := auditItem{
					ExchangeID:     ex.ID,
					Method:         ex.Method,
					URL:            ex.URL,
					BaselineStatus: ex.Status,
					UnauthStatus:   unauthStatus,
					Tags:           ClassifyEndpointParamTags(nil, ex.URL),
				}
				if hadAuth && ex.Status >= 200 && ex.Status < 300 && unauthStatus >= 200 && unauthStatus < 300 && unauthLen > 0 {
					item.SuspectAuthBypass = true
					item.Note = "Endpoint returned 2xx with authentication headers stripped; verify with authz_replay."
				}

				if len(p.LowPrivHeaders) > 0 {
					lowHdrs := cloneHeadersWithOverride(unauthHdrs, p.LowPrivHeaders)
					lowSt, lowLen, _, _, lowErr := execBoundedHTTP(ctx, client, ex.Method, ex.URL, lowHdrs, body)
					if lowErr == nil {
						item.LowPrivStatus = lowSt
						if ex.Status >= 200 && ex.Status < 300 && lowSt >= 200 && lowSt < 300 && lowLen > 0 {
							item.SuspectAuthBypass = true
							item.Note = "Endpoint returned 2xx under low-privilege credentials; verify horizontal/vertical access boundaries."
						}
					}
				}
				if item.SuspectAuthBypass {
					suspectCount++
				}
				audited = append(audited, item)
			}

			if audited == nil {
				audited = []auditItem{}
			}
			return jsonResult(map[string]any{
				"host":          p.Host,
				"audited_count": len(audited),
				"suspect_count": suspectCount,
				"results":       audited,
			})
		},
	)
}
