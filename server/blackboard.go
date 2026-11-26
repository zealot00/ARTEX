package server

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

var globalMemBlackboard = db.NewMemoryBlackboard()

func (s *Server) postBlackboardEntry(in db.BlackboardPostInput) (db.BlackboardEntry, error) {
	if s != nil && s.m != nil && s.m.pg != nil {
		if rec, err := s.m.pg.CreateBlackboardEntry(in); err == nil {
			_, _ = globalMemBlackboard.Post(in)
			return rec, nil
		}
	}
	return globalMemBlackboard.Post(in)
}

func (s *Server) queryBlackboardEntries(taskIDs []int64, kind, state, preconditionTag, query string, limit int) ([]db.BlackboardEntry, error) {
	if s != nil && s.m != nil && s.m.pg != nil {
		if list, err := s.m.pg.QueryBlackboardEntries(taskIDs, kind, state, preconditionTag, query, limit); err == nil {
			return list, nil
		}
	}
	return globalMemBlackboard.Query(taskIDs, kind, state, preconditionTag, query, limit), nil
}

func (s *Server) corroborateBlackboardEntry(id int64, action, newState, author, note, evidenceRef, baselineHash, probeHash string) (db.BlackboardEntry, error) {
	if s != nil && s.m != nil && s.m.pg != nil {
		if rec, err := s.m.pg.CorroborateBlackboardEntry(id, action, newState, author, note, evidenceRef, baselineHash, probeHash); err == nil {
			_, _ = globalMemBlackboard.Corroborate(id, action, newState, author, note, evidenceRef, baselineHash, probeHash)
			return rec, nil
		}
	}
	return globalMemBlackboard.Corroborate(id, action, newState, author, note, evidenceRef, baselineHash, probeHash)
}

func (s *Server) taskLineageIDs(t *Task, taskID int64) []int64 {
	ids := []int64{taskID}
	if t != nil {
		st := t.lifecycleSnapshot()
		seen := map[int64]bool{taskID: true}
		for _, sid := range st.SourceTaskIDs {
			if sid > 0 && !seen[sid] {
				seen[sid] = true
				ids = append(ids, sid)
			}
		}
	}
	return ids
}

func (s *Server) toolBBRecord() actool.CoreTool {
	return wrTool(
		"bb_record",
		"Shared Uncertainty Blackboard (Cairn-style): immediately record an in-progress uncertain observation during exploration without waiting for intent completion. Supports 5 kinds: 'anomaly' (unexpected header, leaked class/path, unused JS secret/param), 'hypothesis' (testable vulnerability hypothesis), 'precondition_need' (bounty for another worker: e.g. need absolute file path, internal port, or token), 'deferred_endpoint' (401/403 or signature-gated endpoint waiting for credentials/signing logic), and 'env_constraint' (WAF/rate-limit quirk). Enforces anti-deception differential baseline & canary quarantine.",
		objSchema(map[string]any{
			"task_id":          strParam("Task ID (numeric string)"),
			"kind":             strParam("One of: anomaly, hypothesis, precondition_need, deferred_endpoint, env_constraint"),
			"target":           strParam("Associated host, endpoint URL, or component name"),
			"topic":            strParam("Concise title of the clue, hypothesis, or deferred surface"),
			"detail":           strParam("Detailed observation, raw clue values, or what is needed to unblock"),
			"precondition_tag": strParam("Optional tag for precondition_need / deferred_endpoint (e.g. 'auth_session', 'admin_token', 'internal_path', 'signing_key', 'internal_pivot')"),
			"evidence_ref":     strParam("Traffic exchange ID, file:line, or command output snippet backing the observation"),
			"author":           strParam("Caller identifier (e.g. 'intent#15' or 'worker')"),
			"baseline_hash":    strParam("Optional benign baseline response hash for anti-deception differential check"),
			"probe_hash":       strParam("Optional test probe response hash (if identical to baseline_hash, entry is automatically quarantined as potential deception/false-positive)"),
		}, "task_id", "kind", "topic"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var p struct {
				TaskID          string `json:"task_id"`
				Kind            string `json:"kind"`
				Target          string `json:"target"`
				Topic           string `json:"topic"`
				Detail          string `json:"detail"`
				PreconditionTag string `json:"precondition_tag"`
				EvidenceRef     string `json:"evidence_ref"`
				Author          string `json:"author"`
				BaselineHash    string `json:"baseline_hash"`
				ProbeHash       string `json:"probe_hash"`
			}
			if err := json.Unmarshal(in, &p); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			tid, err := strconv.ParseInt(strings.TrimSpace(p.TaskID), 10, 64)
			if err != nil || tid <= 0 {
				return actool.Errorf("invalid task_id"), nil
			}
			rec, err := s.postBlackboardEntry(db.BlackboardPostInput{
				TaskID:          tid,
				Kind:            p.Kind,
				Target:          p.Target,
				Topic:           p.Topic,
				Detail:          p.Detail,
				PreconditionTag: p.PreconditionTag,
				EvidenceRef:     p.EvidenceRef,
				Author:          p.Author,
				BaselineHash:    p.BaselineHash,
				ProbeHash:       p.ProbeHash,
			})
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(map[string]any{
				"recorded":    true,
				"quarantined": rec.EpistemicState == db.BBStateQuarantined,
				"entry":       rec,
			})
		},
	)
}

func (s *Server) toolBBSearch() actool.CoreTool {
	return roTool(
		"bb_search",
		"Query the Shared Uncertainty Blackboard across the current task and any linked source tasks. Concurrent workers and planners use this to discover anomalies, open precondition bounties ('precondition_need'), deferred 401/403 endpoints ('deferred_endpoint'), WAF quirks ('env_constraint'), and active hypotheses posted by other workers.",
		objSchema(map[string]any{
			"task_id":          strParam("Task ID (numeric string)"),
			"kind":             strParam("Optional filter: anomaly, hypothesis, precondition_need, deferred_endpoint, env_constraint"),
			"epistemic_state":  strParam("Optional filter: tentative, corroborated, promoted, refuted, quarantined"),
			"precondition_tag": strParam("Optional precondition tag filter (e.g. 'auth_session', 'internal_path', 'signing_key')"),
			"query":            strParam("Optional keyword or host/path substring"),
			"limit":            map[string]any{"type": "integer", "description": "Max entries to return (default 30, max 100)"},
		}, "task_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var p struct {
				TaskID          string `json:"task_id"`
				Kind            string `json:"kind"`
				EpistemicState  string `json:"epistemic_state"`
				PreconditionTag string `json:"precondition_tag"`
				Query           string `json:"query"`
				Limit           int    `json:"limit"`
			}
			if err := json.Unmarshal(in, &p); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			tid, err := strconv.ParseInt(strings.TrimSpace(p.TaskID), 10, 64)
			if err != nil || tid <= 0 {
				return actool.Errorf("invalid task_id"), nil
			}
			var t *Task
			if s.m != nil {
				t = s.m.ResolveTask(strings.TrimSpace(p.TaskID))
			}
			taskIDs := s.taskLineageIDs(t, tid)
			entries, err := s.queryBlackboardEntries(taskIDs, p.Kind, p.EpistemicState, p.PreconditionTag, p.Query, p.Limit)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if entries == nil {
				entries = []db.BlackboardEntry{}
			}
			return jsonResult(map[string]any{
				"task_lineage_ids": taskIDs,
				"count":            len(entries),
				"entries":          entries,
			})
		},
	)
}

func (s *Server) toolBBCorroborate() actool.CoreTool {
	return wrTool(
		"bb_corroborate",
		"Corroborate, refute, promote, or quarantine an existing Shared Uncertainty Blackboard entry with independent evidence from another worker or verification step. Never treat a single worker's tentative summary as verified without independent evidence.",
		objSchema(map[string]any{
			"entry_id":        map[string]any{"type": "integer", "description": "Blackboard entry ID"},
			"epistemic_state": strParam("Target state: corroborated (independent evidence supports it), promoted (converted to fact/finding), refuted (disproved with counter-evidence), or quarantined (suspected deception/canary)"),
			"note":            strParam("What independent check was performed and what it showed"),
			"evidence_ref":    strParam("Traffic exchange ID, file:line, or command output citation"),
			"author":          strParam("Caller identifier (e.g. 'intent#22')"),
			"baseline_hash":   strParam("Optional benign baseline response hash"),
			"probe_hash":      strParam("Optional probe response hash"),
		}, "entry_id", "epistemic_state", "note"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var p struct {
				EntryID        int64  `json:"entry_id"`
				EpistemicState string `json:"epistemic_state"`
				Note           string `json:"note"`
				EvidenceRef    string `json:"evidence_ref"`
				Author         string `json:"author"`
				BaselineHash   string `json:"baseline_hash"`
				ProbeHash      string `json:"probe_hash"`
			}
			if err := json.Unmarshal(in, &p); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if p.EntryID <= 0 {
				return actool.Errorf("valid entry_id is required"), nil
			}
			rec, err := s.corroborateBlackboardEntry(p.EntryID, p.EpistemicState, p.EpistemicState, p.Author, p.Note, p.EvidenceRef, p.BaselineHash, p.ProbeHash)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(map[string]any{
				"updated": true,
				"entry":   rec,
			})
		},
	)
}

func (s *Server) toolInvalidateFactCascade() actool.CoreTool {
	return wrTool(
		"invalidate_fact_cascade",
		"Cascading belief revision tool: when a previously recorded exploration fact or premise is disproved by new evidence, marks that node as 'invalidated', records the counter-evidence, invalidates any cold-digest cache covering it, and automatically halts all downstream 'open' intents that depended on the falsified premise.",
		objSchema(map[string]any{
			"task_id":          strParam("Task ID (numeric string)"),
			"node_id":          map[string]any{"type": "integer", "description": "Exploration node ID (fact/hypothesis) that has been falsified"},
			"reason":           strParam("Why the premise is false"),
			"counter_evidence": strParam("Concrete request/response, traffic ID, or code citation disproving the premise"),
		}, "task_id", "node_id", "reason"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var p struct {
				TaskID          string `json:"task_id"`
				NodeID          int64  `json:"node_id"`
				Reason          string `json:"reason"`
				CounterEvidence string `json:"counter_evidence"`
			}
			if err := json.Unmarshal(in, &p); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if p.NodeID <= 0 {
				return actool.Errorf("node_id must be positive"), nil
			}
			t := s.m.ResolveTask(strings.TrimSpace(p.TaskID))
			if t == nil || t.Store == nil {
				return actool.Errorf("task or exploration store unavailable"), nil
			}
			res, err := t.Store.InvalidateNodeAndCascade(p.NodeID, p.Reason, p.CounterEvidence)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(res)
		},
	)
}

// BlackboardTriageSummary synthesizes unblocked deferred surfaces, open precondition bounties,
// corroborated clues, quarantined deception warnings, and MazeRunner stagnation posture.
type BlackboardTriageSummary struct {
	TotalEntries         int                  `json:"total_entries"`
	UnblockedSurfaces    []db.BlackboardEntry `json:"unblocked_surfaces"`
	OpenPreconditionNeed []db.BlackboardEntry `json:"open_precondition_needs"`
	ActiveHypotheses     []db.BlackboardEntry `json:"active_hypotheses"`
	RecentAnomalies      []db.BlackboardEntry `json:"recent_anomalies"`
	QuarantinedDeception []db.BlackboardEntry `json:"quarantined_deception"`
	StagnationDetected   bool                 `json:"stagnation_detected"`
	StagnationReason     string               `json:"stagnation_reason,omitempty"`
}

func (s *Server) computeBlackboardTriage(t *Task, taskID int64) BlackboardTriageSummary {
	taskIDs := s.taskLineageIDs(t, taskID)
	entries, _ := s.queryBlackboardEntries(taskIDs, "", "", "", "", 80)
	var sum BlackboardTriageSummary
	sum.TotalEntries = len(entries)

	// Determine which precondition tags are now satisfied in this task's environment.
	satisfiedTags := map[string]bool{}
	if s != nil && s.m != nil {
		if s.m.pg != nil {
			if creds, err := s.m.pg.TaskCredentials(taskID); err == nil && len(creds) > 0 {
				satisfiedTags["auth_session"] = true
				satisfiedTags["low_priv_token"] = true
				satisfiedTags["admin_token"] = true
			}
		}
		if s.m.traffic != nil && t != nil {
			if rules := s.m.traffic.ListTaskHostHeaderRules(t.ID); len(rules) > 0 {
				satisfiedTags["auth_session"] = true
				satisfiedTags["low_priv_token"] = true
			}
		}
	}
	if s != nil && s.sessMgr != nil && t != nil {
		for _, sess := range s.sessMgr.List(t.ID) {
			if sess.Status == "open" {
				satisfiedTags["internal_pivot"] = true
			}
		}
	}

	// Any corroborated anomaly/hypothesis with a precondition_tag also satisfies matching needs!
	for _, e := range entries {
		if (e.Kind == db.BBKindAnomaly || e.Kind == db.BBKindHypothesis) &&
			(e.EpistemicState == db.BBStateCorroborated || e.EpistemicState == db.BBStateTentative) &&
			e.PreconditionTag != "" {
			satisfiedTags[e.PreconditionTag] = true
		}
	}

	for _, e := range entries {
		if e.EpistemicState == db.BBStateQuarantined {
			sum.QuarantinedDeception = append(sum.QuarantinedDeception, e)
			continue
		}
		if e.EpistemicState == db.BBStateRefuted || e.EpistemicState == db.BBStatePromoted {
			continue
		}
		switch e.Kind {
		case db.BBKindDeferredEndpoint:
			if e.PreconditionTag != "" && satisfiedTags[e.PreconditionTag] {
				sum.UnblockedSurfaces = append(sum.UnblockedSurfaces, e)
			}
		case db.BBKindPreconditionNeed:
			if e.PreconditionTag != "" && satisfiedTags[e.PreconditionTag] {
				sum.UnblockedSurfaces = append(sum.UnblockedSurfaces, e)
			} else {
				sum.OpenPreconditionNeed = append(sum.OpenPreconditionNeed, e)
			}
		case db.BBKindHypothesis:
			sum.ActiveHypotheses = append(sum.ActiveHypotheses, e)
		case db.BBKindAnomaly:
			sum.RecentAnomalies = append(sum.RecentAnomalies, e)
		}
	}

	// MazeRunner stagnation check: if >=3 intents finished with 0 findings, or there are
	// unblocked surfaces / unresolved hypotheses waiting to be synthesized, flag stagnation review.
	if t != nil && t.Store != nil {
		doneCount, err1 := t.Store.CountFinishedIntents()
		findings, err2 := t.Store.ListByKind("finding", 10)
		if err1 == nil && err2 == nil && doneCount >= 3 && len(findings) == 0 {
			sum.StagnationDetected = true
			sum.StagnationReason = fmt.Sprintf("%d intents completed with 0 confirmed findings; switch to MazeRunner failure-review mode (synthesize blackboard anomalies/hypotheses, fulfill open precondition bounties, or pivot to uncovered assets instead of repeating blocked probes)", doneCount)
		}
	}
	if !sum.StagnationDetected && len(sum.UnblockedSurfaces) > 0 {
		sum.StagnationDetected = true
		sum.StagnationReason = fmt.Sprintf("%d previously deferred/blocked surfaces now have their preconditions satisfied and are ready for immediate re-verification", len(sum.UnblockedSurfaces))
	}
	return sum
}
