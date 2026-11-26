package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

// CandidateGateDecision represents the Dispatcher Commit Gate verdict before a finding
// is allowed to enter the formal findings table.
type CandidateGateDecision struct {
	Decision          string              `json:"decision"` // "approve_for_report" | "downgrade_to_blackboard_hypothesis" | "quarantine_deception"
	Reason            string              `json:"reason"`
	BlackboardEntryID int64               `json:"blackboard_entry_id,omitempty"`
	Entry             *db.BlackboardEntry `json:"blackboard_entry,omitempty"`
}

func (s *Server) toolVerifyCandidateFinding() actool.CoreTool {
	return wrTool(
		"verify_candidate_finding",
		"Dispatcher Commit Gate: validates a candidate vulnerability BEFORE report_finding. Enforces verifiable evidence anchors (traffic_refs, command output, or code file:line), proof basis ('executed-live' / 'executed-lab' vs 'static-analysis-unexecuted'), and anti-deception differential baseline/canary checks. Unexecuted static leads are automatically downgraded to Shared Blackboard hypotheses and suspected decoys are quarantined so formal findings stay 100% clean.",
		objSchema(map[string]any{
			"task_id":         strParam("Task ID (numeric string)"),
			"target":          strParam("Affected endpoint, host, or file:line"),
			"title":           strParam("Candidate vulnerability summary"),
			"proof_basis":     strParam("One of: executed-live, executed-lab, static-analysis-unexecuted"),
			"measured_impact": strParam("Quantified impact with denominator (e.g. '3 of 5 requests returned other-tenant records')"),
			"evidence_ref":    strParam("Traffic exchange ID, command output snippet, or file:line citation"),
			"baseline_hash":   strParam("Optional benign baseline response hash for differential verification"),
			"probe_hash":      strParam("Optional exploit probe response hash"),
		}, "task_id", "target", "title", "proof_basis"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var p struct {
				TaskID         string `json:"task_id"`
				Target         string `json:"target"`
				Title          string `json:"title"`
				ProofBasis     string `json:"proof_basis"`
				MeasuredImpact string `json:"measured_impact"`
				EvidenceRef    string `json:"evidence_ref"`
				BaselineHash   string `json:"baseline_hash"`
				ProbeHash      string `json:"probe_hash"`
			}
			if err := json.Unmarshal(in, &p); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			tid, err := strconv.ParseInt(strings.TrimSpace(p.TaskID), 10, 64)
			if err != nil || tid <= 0 {
				return actool.Errorf("invalid task_id"), nil
			}
			basis := strings.ToLower(strings.TrimSpace(p.ProofBasis))
			ev := strings.TrimSpace(p.EvidenceRef)
			impact := strings.TrimSpace(p.MeasuredImpact)

			// 1. Anti-Deception Gate (differential baseline hash + Gingerbread/Canary tokens).
			if q, reason := db.DetectDeceptionIndicators(p.Title+" "+ev+" "+impact, p.BaselineHash, p.ProbeHash); q {
				rec, _ := s.postBlackboardEntry(db.BlackboardPostInput{
					TaskID:       tid,
					Kind:         db.BBKindHypothesis,
					Target:       p.Target,
					Topic:        p.Title,
					Detail:       "Quarantined by Dispatcher Commit Gate: " + reason,
					EvidenceRef:  ev,
					Author:       "commit-gate",
					BaselineHash: p.BaselineHash,
					ProbeHash:    p.ProbeHash,
				})
				return jsonResult(CandidateGateDecision{
					Decision:          "quarantine_deception",
					Reason:            reason,
					BlackboardEntryID: rec.ID,
					Entry:             &rec,
				})
			}

			// 2. Require concrete evidence anchor & executed proof for formal report approval.
			if basis != "executed-live" && basis != "executed-lab" {
				reason := fmt.Sprintf("proof_basis=%q is not dynamically executed; downgraded to Shared Blackboard hypothesis for live verification", p.ProofBasis)
				rec, _ := s.postBlackboardEntry(db.BlackboardPostInput{
					TaskID:      tid,
					Kind:        db.BBKindHypothesis,
					Target:      p.Target,
					Topic:       p.Title,
					Detail:      reason + " | impact=" + impact,
					EvidenceRef: ev,
					Author:      "commit-gate",
				})
				return jsonResult(CandidateGateDecision{
					Decision:          "downgrade_to_blackboard_hypothesis",
					Reason:            reason,
					BlackboardEntryID: rec.ID,
					Entry:             &rec,
				})
			}
			if ev == "" || impact == "" {
				reason := "missing concrete evidence_ref or measured_impact; downgraded to Shared Blackboard hypothesis until reproducible evidence is captured"
				rec, _ := s.postBlackboardEntry(db.BlackboardPostInput{
					TaskID:      tid,
					Kind:        db.BBKindHypothesis,
					Target:      p.Target,
					Topic:       p.Title,
					Detail:      reason,
					EvidenceRef: ev,
					Author:      "commit-gate",
				})
				return jsonResult(CandidateGateDecision{
					Decision:          "downgrade_to_blackboard_hypothesis",
					Reason:            reason,
					BlackboardEntryID: rec.ID,
					Entry:             &rec,
				})
			}

			return jsonResult(CandidateGateDecision{
				Decision: "approve_for_report",
				Reason:   "Candidate passed executed proof basis, evidence anchor, measured impact, and anti-deception differential gates; safe to call report_finding.",
			})
		},
	)
}

func (s *Server) toolBootstrapTargetSurface() actool.CoreTool {
	return wrTool(
		"bootstrap_target_surface",
		"Cairn-inspired Bootstrap fast-path: in one bounded step at task startup, profiles an authorized target URL/host (homepage status/headers/title, OpenAPI/Swagger & JS bundle contract extraction into the asset graph, open-source repository candidate matching, and matching ./pocs baseline preview) while initializing the L1 Focused Persistent Solver state so Planner Round 1 immediately starts with rich facts instead of cold-starting blind.",
		objSchema(map[string]any{
			"task_id":  strParam("Task ID (numeric string)"),
			"base_url": strParam("Authorized target base URL (e.g. 'http://10.10.1.5:8080')"),
			"ports":    map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "Optional known open ports on this host"},
			"techs":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Optional known technology/product names"},
		}, "task_id", "base_url"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var p struct {
				TaskID  string   `json:"task_id"`
				BaseURL string   `json:"base_url"`
				Ports   []int    `json:"ports"`
				Techs   []string `json:"techs"`
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
					return actool.Errorf(fmt.Sprintf("electronic fence blocked bootstrap_target_surface: %s", reason)), nil
				}
			}
			s.recordTaskOutbound(t, "bootstrap_target_surface", u.Scheme, p.BaseURL, "GET", "Bootstrap initial target profiling")

			client := safeHTTPClient(8 * time.Second)
			var statusCode int
			var serverHeader, poweredBy string
			var discovered []DiscoveredContractEndpoint
			seenKey := map[string]bool{}
			addEP := func(ep DiscoveredContractEndpoint) {
				k := ep.Method + " " + ep.Path
				if !seenKey[k] && len(discovered) < 80 {
					seenKey[k] = true
					discovered = append(discovered, ep)
				}
			}

			// 1. Homepage & header fingerprint + JS bundle routes.
			var pageSnippet string
			if req, reqErr := http.NewRequestWithContext(ctx, "GET", p.BaseURL+"/", nil); reqErr == nil {
				if resp, doErr := client.Do(req); doErr == nil {
					statusCode = resp.StatusCode
					serverHeader = resp.Header.Get("Server")
					poweredBy = resp.Header.Get("X-Powered-By")
					body, _ := io.ReadAll(io.LimitReader(resp.Body, maxContractBytes))
					resp.Body.Close()
					htmlText := string(body)
					if len(htmlText) > 512 {
						pageSnippet = htmlText[:512]
					} else {
						pageSnippet = htmlText
					}
					for _, ep := range ParseJSBundleEndpoints(p.BaseURL, "html", htmlText) {
						addEP(ep)
					}
				}
			}

			// 2. Quick OpenAPI/Swagger check.
			for _, specPath := range []string{"/v3/api-docs", "/swagger.json", "/openapi.json"} {
				if req, reqErr := http.NewRequestWithContext(ctx, "GET", p.BaseURL+specPath, nil); reqErr == nil {
					if resp, doErr := client.Do(req); doErr == nil {
						body, _ := io.ReadAll(io.LimitReader(resp.Body, maxContractBytes))
						resp.Body.Close()
						if resp.StatusCode == 200 && len(body) > 0 {
							for _, ep := range ParseOpenAPIEndpoints(p.BaseURL, body) {
								addEP(ep)
							}
						}
					}
				}
			}

			// 3. Register discovered endpoints into asset graph if available.
			tid, _ := strconv.ParseInt(t.ID, 10, 64)
			registered := 0
			if s.m != nil && s.m.assets != nil && tid > 0 {
				for _, ep := range discovered {
					if _, upErr := s.m.assets.UpsertEndpoint(db.UpsertEndpointReq{
						URL:    ep.URL,
						Method: ep.Method,
						Params: ep.Params,
						TaskID: tid,
					}); upErr == nil {
						registered++
					}
				}
			}

			// 4. Match OSS repo candidates and baseline PoCs.
			var ossMatches []OSSRepoMapping
			checkStrings := append([]string{serverHeader, poweredBy, pageSnippet}, p.Techs...)
			seenOSS := map[string]bool{}
			for _, cs := range checkStrings {
				if m, ok := MatchKnownOSSRepo(cs); ok && !seenOSS[m.Component] {
					seenOSS[m.Component] = true
					ossMatches = append(ossMatches, m)
				}
			}
			baselinePocs := matchBaselinePocs(loadPocsFromDir(pocsDir()), p.Ports, p.Techs, 10)
			var pocNames []string
			for _, bp := range baselinePocs {
				pocNames = append(pocNames, bp.Name)
			}

			solverState := globalSolverMgr.Snapshot(tid)
			return jsonResult(map[string]any{
				"base_url":              p.BaseURL,
				"http_status":           statusCode,
				"server_header":         serverHeader,
				"x_powered_by":          poweredBy,
				"discovered_endpoints":  len(discovered),
				"registered_into_graph": registered,
				"endpoints":             discovered,
				"oss_repo_candidates":   ossMatches,
				"matched_baseline_pocs": pocNames,
				"solver_tier":           solverState.CurrentTierLabel,
				"next_step":             "Use run_infra_baseline on matched PoCs, oss_fetch_source on OSS candidates, and traffic_fuzz_audit/authz_replay on discovered endpoints.",
			})
		},
	)
}
