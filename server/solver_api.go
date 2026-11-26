package server

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
)

func solverStateToDBRecord(st SolverState) db.SolverStateRecord {
	pruned := make([]db.SolverPrunedMechanismRecord, 0, len(st.PrunedMechanisms))
	for _, pm := range st.PrunedMechanisms {
		pruned = append(pruned, db.SolverPrunedMechanismRecord{
			Target:      pm.Target,
			Mechanism:   pm.Mechanism,
			Tier:        int(pm.Tier),
			Reason:      pm.Reason,
			EvidenceRef: pm.EvidenceRef,
			Author:      pm.Author,
			Timestamp:   pm.Timestamp,
		})
	}
	return db.SolverStateRecord{
		TaskID:           st.TaskID,
		FocusedMode:      st.FocusedMode,
		CurrentTier:      int(st.CurrentTier),
		CurrentTierLabel: st.CurrentTier.Label(),
		PrunedMechanisms: pruned,
		EscalationLog:    append([]string(nil), st.EscalationLog...),
		UpdatedAt:        st.UpdatedAt,
	}
}

func (s *Server) persistSolverState(st SolverState) {
	if s != nil && s.m != nil && s.m.pg != nil && st.TaskID > 0 {
		_ = s.m.pg.UpsertTaskSolverState(solverStateToDBRecord(st))
	}
}

func (s *Server) loadSolverStateRecord(taskID int64) *db.SolverStateRecord {
	st := globalSolverMgr.Snapshot(taskID)
	if s != nil && s.m != nil && s.m.pg != nil && taskID > 0 {
		if dbRec, err := s.m.pg.GetTaskSolverState(taskID); err == nil && dbRec != nil {
			if dbRec.CurrentTier >= int(st.CurrentTier) && len(dbRec.PrunedMechanisms) >= len(st.PrunedMechanisms) {
				return dbRec
			}
		}
	}
	rec := solverStateToDBRecord(st)
	return &rec
}

// GET /api/tasks/{id}/solver — returns Focused Persistent Solver posture, Shared Uncertainty
// Blackboard entries, triage summary, and active concurrent resource leases.
func (s *Server) getTaskSolver(w http.ResponseWriter, r *http.Request) {
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
	solverRec := s.loadSolverStateRecord(tid)
	taskIDs := s.taskLineageIDs(t, tid)
	entries, _ := s.queryBlackboardEntries(taskIDs, "", "", "", "", 80)
	if entries == nil {
		entries = []db.BlackboardEntry{}
	}
	triage := s.computeBlackboardTriage(t, tid)
	leases := globalLeaseMgr.List(t.ID)
	if leases == nil {
		leases = []ResourceLease{}
	}
	writeJSON(w, 200, map[string]any{
		"solver":     solverRec,
		"blackboard": entries,
		"triage":     triage,
		"leases":     leases,
	})
}

// POST /api/tasks/{id}/solver/escalate — operator manually escalates solver tier (L2..L5).
func (s *Server) escalateTaskSolver(w http.ResponseWriter, r *http.Request) {
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
	var req struct {
		TargetTier int    `json:"target_tier"`
		Reason     string `json:"reason"`
	}
	if err := decode(w, r, &req); err != nil {
		writeErr(w, 400, "invalid JSON")
		return
	}
	st, err := globalSolverMgr.Escalate(tid, SolverTier(req.TargetTier), req.Reason)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	s.persistSolverState(st)
	writeJSON(w, 200, map[string]any{"solver": solverStateToDBRecord(st)})
}

// POST /api/tasks/{id}/blackboard — operator injects a clue, hypothesis, or precondition onto the blackboard.
func (s *Server) postTaskBlackboard(w http.ResponseWriter, r *http.Request) {
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
	var req struct {
		Kind            string `json:"kind"`
		Target          string `json:"target"`
		Topic           string `json:"topic"`
		Detail          string `json:"detail"`
		PreconditionTag string `json:"precondition_tag"`
		EvidenceRef     string `json:"evidence_ref"`
	}
	if err := decode(w, r, &req); err != nil {
		writeErr(w, 400, "invalid JSON")
		return
	}
	if strings.TrimSpace(req.Kind) == "" {
		req.Kind = db.BBKindHypothesis
	}
	rec, err := s.postBlackboardEntry(db.BlackboardPostInput{
		TaskID:          tid,
		Kind:            req.Kind,
		Target:          req.Target,
		Topic:           req.Topic,
		Detail:          req.Detail,
		PreconditionTag: req.PreconditionTag,
		EvidenceRef:     req.EvidenceRef,
		Author:          "operator",
	})
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 201, map[string]any{"entry": rec})
}
