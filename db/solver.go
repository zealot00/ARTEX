package db

import (
	"database/sql"
	"encoding/json"
)

// SolverPrunedMechanismRecord is the persisted representation of a disproved attack mechanism.
type SolverPrunedMechanismRecord struct {
	Target      string `json:"target"`
	Mechanism   string `json:"mechanism"`
	Tier        int    `json:"tier"`
	Reason      string `json:"reason"`
	EvidenceRef string `json:"evidence_ref"`
	Author      string `json:"author"`
	Timestamp   string `json:"timestamp"`
}

// SolverStateRecord is the persisted representation of a task's Focused Persistent Solver state.
type SolverStateRecord struct {
	TaskID           int64                         `json:"task_id"`
	FocusedMode      bool                          `json:"focused_mode"`
	CurrentTier      int                           `json:"current_tier"`
	CurrentTierLabel string                        `json:"current_tier_label"`
	PrunedMechanisms []SolverPrunedMechanismRecord `json:"pruned_mechanisms"`
	EscalationLog    []string                      `json:"escalation_log"`
	UpdatedAt        string                        `json:"updated_at"`
}

func SolverTierName(tier int) string {
	switch tier {
	case 1:
		return "L1_BASELINE"
	case 2:
		return "L2_DEEP_BIZ_PROTO"
	case 3:
		return "L3_WHITEBOX_GRAYBOX"
	case 4:
		return "L4_TECHNIQUE_SYNTHESIS"
	case 5:
		return "L5_ADJACENT_PIVOT"
	default:
		return "L1_BASELINE"
	}
}

// GetTaskSolverState loads a task's persisted solver state from PostgreSQL.
func (d *DB) GetTaskSolverState(taskID int64) (*SolverStateRecord, error) {
	if taskID <= 0 {
		return nil, nil
	}
	var rec SolverStateRecord
	var prunedRaw, logRaw []byte
	err := d.QueryRow(`
SELECT task_id, focused_mode, current_tier, pruned_mechanisms, escalation_log,
       to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
FROM task_solver_states
WHERE task_id = $1`, taskID).Scan(
		&rec.TaskID, &rec.FocusedMode, &rec.CurrentTier, &prunedRaw, &logRaw, &rec.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	rec.CurrentTierLabel = SolverTierName(rec.CurrentTier)
	_ = json.Unmarshal(prunedRaw, &rec.PrunedMechanisms)
	_ = json.Unmarshal(logRaw, &rec.EscalationLog)
	if rec.PrunedMechanisms == nil {
		rec.PrunedMechanisms = []SolverPrunedMechanismRecord{}
	}
	if rec.EscalationLog == nil {
		rec.EscalationLog = []string{}
	}
	return &rec, nil
}

// UpsertTaskSolverState persists a task's solver escalation stage and pruned mechanisms.
func (d *DB) UpsertTaskSolverState(rec SolverStateRecord) error {
	if rec.TaskID <= 0 {
		return nil
	}
	if rec.CurrentTier < 1 {
		rec.CurrentTier = 1
	}
	if rec.CurrentTier > 5 {
		rec.CurrentTier = 5
	}
	prunedBytes, _ := json.Marshal(rec.PrunedMechanisms)
	logBytes, _ := json.Marshal(rec.EscalationLog)
	_, err := d.Exec(`
INSERT INTO task_solver_states (task_id, focused_mode, current_tier, pruned_mechanisms, escalation_log)
VALUES ($1, $2, $3, $4::jsonb, $5::jsonb)
ON CONFLICT (task_id) DO UPDATE SET
    focused_mode = EXCLUDED.focused_mode,
    current_tier = EXCLUDED.current_tier,
    pruned_mechanisms = EXCLUDED.pruned_mechanisms,
    escalation_log = EXCLUDED.escalation_log`,
		rec.TaskID, rec.FocusedMode, rec.CurrentTier, string(prunedBytes), string(logBytes),
	)
	return err
}
