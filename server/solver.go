package server

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	actool "github.com/Autumn-27/norma/tool"
)

// SolverTier represents the 5-stage progressive technique escalation ladder
// for Focused Persistent Solving ("唯一求解").
type SolverTier int

const (
	TierL1Baseline           SolverTier = 1
	TierL2DeepBizProto       SolverTier = 2
	TierL3WhiteboxGraybox    SolverTier = 3
	TierL4TechniqueSynthesis SolverTier = 4
	TierL5AdjacentPivot      SolverTier = 5
)

func (t SolverTier) Label() string {
	switch t {
	case TierL1Baseline:
		return "L1_BASELINE"
	case TierL2DeepBizProto:
		return "L2_DEEP_BIZ_PROTO"
	case TierL3WhiteboxGraybox:
		return "L3_WHITEBOX_GRAYBOX"
	case TierL4TechniqueSynthesis:
		return "L4_TECHNIQUE_SYNTHESIS"
	case TierL5AdjacentPivot:
		return "L5_ADJACENT_PIVOT"
	default:
		return "L1_BASELINE"
	}
}

func (t SolverTier) Directive() string {
	switch t {
	case TierL1Baseline:
		return "Standardized surface & baseline: run bootstrap_target_surface / extract_web_contracts, run_infra_baseline, search_pocs + run_poc, and credential/default-config checks."
	case TierL2DeepBizProto:
		return "Deep business-logic & protocol edge cases: run traffic_fuzz_audit, authz_replay (unauth/low-priv/path-bypass), race_probe, state-machine step skipping, HTTP parsing/encoding/Content-Type switching, and frontend JS signing reverse-engineering."
	case TierL3WhiteboxGraybox:
		return "White-box & gray-box source linkage: fetch matching open-source component source via oss_fetch_source (or inspect workspace/JS/archive), run code_scan_semgrep + code_map_entrypoints + code_scan_sinks + code_audit_auth_gaps, and convert code paths into live verification probes."
	case TierL4TechniqueSynthesis:
		return "Dynamic technique discovery & self-synthesis: existing canned PoCs/tools have not solved the goal. Synthesize blackboard anomalies, env_constraint (WAF/filter rules), error traces, and protocol quirks to author custom tailored Python/Nuclei verification scripts via run_poc(inline_kind, inline_content) and persist verified scripts via save_poc."
	case TierL5AdjacentPivot:
		return "Adjacent/lateral pivot solving: direct paths on the primary target are heavily pruned. Without abandoning the primary goal, expand to strongly coupled in-fence adjacent surfaces (shared DB/Redis/MQ, config centers, CI/CD, sibling services, backup/log leaks, credential reuse) to acquire indirect leverage, then immediately pivot back to solve the primary goal."
	default:
		return ""
	}
}

// PrunedMechanism records an attack mechanism thoroughly tested and disproved on a target,
// preventing infinite-solving loops from repeating synonymous failed attempts.
type PrunedMechanism struct {
	Target      string     `json:"target"`
	Mechanism   string     `json:"mechanism"`
	Tier        SolverTier `json:"tier"`
	Reason      string     `json:"reason"`
	EvidenceRef string     `json:"evidence_ref"`
	Author      string     `json:"author"`
	Timestamp   string     `json:"timestamp"`
}

// SolverState tracks a task's Focused Persistent Solving posture and 5-tier escalation state.
type SolverState struct {
	TaskID           int64             `json:"task_id"`
	FocusedMode      bool              `json:"focused_mode"`
	CurrentTier      SolverTier        `json:"current_tier"`
	CurrentTierLabel string            `json:"current_tier_label"`
	TierDirective    string            `json:"tier_directive"`
	PrunedMechanisms []PrunedMechanism `json:"pruned_mechanisms"`
	EscalationLog    []string          `json:"escalation_log"`
	UpdatedAt        string            `json:"updated_at"`
}

type SolverManager struct {
	mu     sync.Mutex
	states map[int64]*SolverState
}

var globalSolverMgr = &SolverManager{states: map[int64]*SolverState{}}

func (m *SolverManager) getOrInitLocked(taskID int64) *SolverState {
	st, ok := m.states[taskID]
	if !ok {
		st = &SolverState{
			TaskID:           taskID,
			FocusedMode:      true,
			CurrentTier:      TierL1Baseline,
			CurrentTierLabel: TierL1Baseline.Label(),
			TierDirective:    TierL1Baseline.Directive(),
			PrunedMechanisms: []PrunedMechanism{},
			EscalationLog:    []string{},
			UpdatedAt:        time.Now().UTC().Format(time.RFC3339),
		}
		m.states[taskID] = st
	}
	return st
}

func cloneSolverState(st *SolverState) SolverState {
	cp := *st
	cp.CurrentTierLabel = st.CurrentTier.Label()
	cp.TierDirective = st.CurrentTier.Directive()
	cp.PrunedMechanisms = append([]PrunedMechanism(nil), st.PrunedMechanisms...)
	cp.EscalationLog = append([]string(nil), st.EscalationLog...)
	return cp
}

// Snapshot returns a thread-safe copy of the task's solver state.
func (m *SolverManager) Snapshot(taskID int64) SolverState {
	m.mu.Lock()
	defer m.mu.Unlock()
	return cloneSolverState(m.getOrInitLocked(taskID))
}

// PruneMechanism records a disproved mechanism and automatically escalates the solver
// tier when >=2 distinct mechanisms have been pruned at the current tier.
func (m *SolverManager) PruneMechanism(taskID int64, target, mechanism, reason, evidenceRef, author string) (SolverState, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := m.getOrInitLocked(taskID)
	now := time.Now().UTC().Format(time.RFC3339)
	if strings.TrimSpace(author) == "" {
		author = "worker"
	}
	entry := PrunedMechanism{
		Target:      strings.TrimSpace(target),
		Mechanism:   strings.TrimSpace(mechanism),
		Tier:        st.CurrentTier,
		Reason:      strings.TrimSpace(reason),
		EvidenceRef: strings.TrimSpace(evidenceRef),
		Author:      strings.TrimSpace(author),
		Timestamp:   now,
	}
	// Deduplicate by (target, mechanism).
	dup := false
	for _, existing := range st.PrunedMechanisms {
		if strings.EqualFold(existing.Target, entry.Target) && strings.EqualFold(existing.Mechanism, entry.Mechanism) {
			dup = true
			break
		}
	}
	if !dup {
		st.PrunedMechanisms = append(st.PrunedMechanisms, entry)
	}
	st.UpdatedAt = now

	// Count pruned mechanisms at current tier; auto-escalate if >=2 pruned at this tier.
	prunedHere := 0
	for _, pm := range st.PrunedMechanisms {
		if pm.Tier == st.CurrentTier {
			prunedHere++
		}
	}
	escalated := false
	if prunedHere >= 2 && st.CurrentTier < TierL5AdjacentPivot {
		prev := st.CurrentTier
		st.CurrentTier++
		st.CurrentTierLabel = st.CurrentTier.Label()
		st.TierDirective = st.CurrentTier.Directive()
		st.EscalationLog = append(st.EscalationLog, fmt.Sprintf("%s: auto-escalated %s -> %s after %d mechanisms pruned at %s", now, prev.Label(), st.CurrentTier.Label(), prunedHere, prev.Label()))
		escalated = true
	}
	return cloneSolverState(st), escalated
}

// Escalate manually advances the solver to targetTier (must be strictly higher and <= L5).
func (m *SolverManager) Escalate(taskID int64, targetTier SolverTier, reason string) (SolverState, error) {
	if targetTier < TierL1Baseline || targetTier > TierL5AdjacentPivot {
		return SolverState{}, fmt.Errorf("target_tier must be between 1 and 5")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	st := m.getOrInitLocked(taskID)
	if targetTier <= st.CurrentTier {
		return cloneSolverState(st), nil
	}
	now := time.Now().UTC().Format(time.RFC3339)
	prev := st.CurrentTier
	st.CurrentTier = targetTier
	st.CurrentTierLabel = st.CurrentTier.Label()
	st.TierDirective = st.CurrentTier.Directive()
	st.UpdatedAt = now
	if strings.TrimSpace(reason) == "" {
		reason = "explicit escalation to expand attack techniques"
	}
	st.EscalationLog = append(st.EscalationLog, fmt.Sprintf("%s: escalated %s -> %s (%s)", now, prev.Label(), st.CurrentTier.Label(), strings.TrimSpace(reason)))
	return cloneSolverState(st), nil
}

// EvaluateProgressAndAutoEscalate inspects finished intent count vs findings and
// automatically advances the tier if the task is spinning without confirmed findings.
func (m *SolverManager) EvaluateProgressAndAutoEscalate(taskID int64, doneIntents, findingsCount int) SolverState {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := m.getOrInitLocked(taskID)
	if findingsCount == 0 && st.CurrentTier < TierL5AdjacentPivot {
		// Auto-escalate every 3 completed intents with 0 findings so the solver never stalls in L1/L2.
		desiredTier := SolverTier(1 + doneIntents/3)
		if desiredTier > TierL5AdjacentPivot {
			desiredTier = TierL5AdjacentPivot
		}
		if desiredTier > st.CurrentTier {
			now := time.Now().UTC().Format(time.RFC3339)
			prev := st.CurrentTier
			st.CurrentTier = desiredTier
			st.CurrentTierLabel = st.CurrentTier.Label()
			st.TierDirective = st.CurrentTier.Directive()
			st.UpdatedAt = now
			st.EscalationLog = append(st.EscalationLog, fmt.Sprintf("%s: auto-escalated %s -> %s (%d intents finished with 0 findings)", now, prev.Label(), st.CurrentTier.Label(), doneIntents))
		}
	}
	return cloneSolverState(st)
}

func (s *Server) toolSolverStatus() actool.CoreTool {
	return roTool(
		"solver_status",
		"Focused Persistent Solver ('唯一求解') posture tool: returns the task's current 5-tier technique escalation stage (L1_BASELINE -> L2_DEEP_BIZ_PROTO -> L3_WHITEBOX_GRAYBOX -> L4_TECHNIQUE_SYNTHESIS -> L5_ADJACENT_PIVOT), the active tier directive, and all pruned mechanisms so Planner/Workers pursue orthogonal unexplored techniques instead of stopping early or repeating failed probes.",
		objSchema(map[string]any{
			"task_id": strParam("Task ID (numeric string)"),
		}, "task_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var p struct {
				TaskID string `json:"task_id"`
			}
			if err := json.Unmarshal(in, &p); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			tid, err := strconv.ParseInt(strings.TrimSpace(p.TaskID), 10, 64)
			if err != nil || tid <= 0 {
				return actool.Errorf("invalid task_id"), nil
			}
			return jsonResult(globalSolverMgr.Snapshot(tid))
		},
	)
}

func (s *Server) toolSolverPruneMechanism() actool.CoreTool {
	return wrTool(
		"solver_prune_mechanism",
		"Prunes a thoroughly tested and disproved attack mechanism on a target (e.g. 'SQLi on /login parameter user: verified parameterized query') with mandatory counter-evidence. Prevents repetitive probes during persistent solving and automatically escalates the solver to the next technique tier (L1->L5) when the current tier is exhausted.",
		objSchema(map[string]any{
			"task_id":      strParam("Task ID (numeric string)"),
			"target":       strParam("Target host, URL, or endpoint"),
			"mechanism":    strParam("Specific vulnerability class / technique pruned (e.g. 'sqli_error_based', 'default_creds_ssh', 'unauth_api_access')"),
			"reason":       strParam("Why this mechanism is ruled out"),
			"evidence_ref": strParam("Concrete evidence (traffic_id, status/response proof, or code file:line)"),
			"author":       strParam("Caller identifier (e.g. 'intent#12')"),
		}, "task_id", "target", "mechanism", "reason", "evidence_ref"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var p struct {
				TaskID      string `json:"task_id"`
				Target      string `json:"target"`
				Mechanism   string `json:"mechanism"`
				Reason      string `json:"reason"`
				EvidenceRef string `json:"evidence_ref"`
				Author      string `json:"author"`
			}
			if err := json.Unmarshal(in, &p); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			tid, err := strconv.ParseInt(strings.TrimSpace(p.TaskID), 10, 64)
			if err != nil || tid <= 0 {
				return actool.Errorf("invalid task_id"), nil
			}
			if strings.TrimSpace(p.Target) == "" || strings.TrimSpace(p.Mechanism) == "" || strings.TrimSpace(p.EvidenceRef) == "" {
				return actool.Errorf("target, mechanism, and evidence_ref are required to prune a mechanism"), nil
			}
			st, escalated := globalSolverMgr.PruneMechanism(tid, p.Target, p.Mechanism, p.Reason, p.EvidenceRef, p.Author)
			s.persistSolverState(st)
			return jsonResult(map[string]any{
				"pruned":         true,
				"auto_escalated": escalated,
				"solver_state":   st,
			})
		},
	)
}

func (s *Server) toolSolverEscalate() actool.CoreTool {
	return wrTool(
		"solver_escalate",
		"Explicitly advances the Focused Persistent Solver to a higher technique expansion tier (2=L2_DEEP_BIZ_PROTO, 3=L3_WHITEBOX_GRAYBOX, 4=L4_TECHNIQUE_SYNTHESIS custom script/PoC authoring, 5=L5_ADJACENT_PIVOT lateral/adjacent leverage) when lower-tier techniques are blocked.",
		objSchema(map[string]any{
			"task_id":     strParam("Task ID (numeric string)"),
			"target_tier": map[string]any{"type": "integer", "description": "Target escalation tier (2, 3, 4, or 5)"},
			"reason":      strParam("Why escalating to this tier is needed"),
		}, "task_id", "target_tier"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var p struct {
				TaskID     string `json:"task_id"`
				TargetTier int    `json:"target_tier"`
				Reason     string `json:"reason"`
			}
			if err := json.Unmarshal(in, &p); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			tid, err := strconv.ParseInt(strings.TrimSpace(p.TaskID), 10, 64)
			if err != nil || tid <= 0 {
				return actool.Errorf("invalid task_id"), nil
			}
			st, err := globalSolverMgr.Escalate(tid, SolverTier(p.TargetTier), p.Reason)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			s.persistSolverState(st)
			return jsonResult(st)
		},
	)
}
