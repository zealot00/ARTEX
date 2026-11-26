package db

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	BBKindAnomaly          = "anomaly"
	BBKindHypothesis       = "hypothesis"
	BBKindPreconditionNeed = "precondition_need"
	BBKindDeferredEndpoint = "deferred_endpoint"
	BBKindEnvConstraint    = "env_constraint"

	BBStateTentative    = "tentative"
	BBStateCorroborated = "corroborated"
	BBStatePromoted     = "promoted"
	BBStateRefuted      = "refuted"
	BBStateQuarantined  = "quarantined"
)

var (
	ErrBBInvalidKind  = errors.New("invalid blackboard kind (must be anomaly, hypothesis, precondition_need, deferred_endpoint, or env_constraint)")
	ErrBBInvalidState = errors.New("invalid epistemic_state (must be tentative, corroborated, promoted, refuted, or quarantined)")
	ErrBBEmptyTopic   = errors.New("blackboard topic is required")
	ErrBBNotFound     = errors.New("blackboard entry not found")
)

// BlackboardCorroboration records one follow-up observation, proof, or refutation
// appended by a concurrent worker or subsequent task round.
type BlackboardCorroboration struct {
	Author      string `json:"author"`
	Action      string `json:"action"` // "corroborate" | "refute" | "promote" | "quarantine"
	Note        string `json:"note"`
	EvidenceRef string `json:"evidence_ref,omitempty"`
	Timestamp   string `json:"timestamp"`
}

// BlackboardEntry represents one evolving unit of uncertain knowledge on the shared blackboard.
type BlackboardEntry struct {
	ID              int64                     `json:"id"`
	TaskID          int64                     `json:"task_id"`
	Kind            string                    `json:"kind"`
	EpistemicState  string                    `json:"epistemic_state"`
	Target          string                    `json:"target"`
	Topic           string                    `json:"topic"`
	Detail          string                    `json:"detail"`
	PreconditionTag string                    `json:"precondition_tag,omitempty"`
	EvidenceRef     string                    `json:"evidence_ref,omitempty"`
	Author          string                    `json:"author"`
	Corroborations  []BlackboardCorroboration `json:"corroborations"`
	CreatedAt       string                    `json:"created_at"`
	UpdatedAt       string                    `json:"updated_at"`
}

// BlackboardPostInput is the input for creating a new blackboard entry.
type BlackboardPostInput struct {
	TaskID          int64  `json:"task_id"`
	Kind            string `json:"kind"`
	Target          string `json:"target"`
	Topic           string `json:"topic"`
	Detail          string `json:"detail"`
	PreconditionTag string `json:"precondition_tag"`
	EvidenceRef     string `json:"evidence_ref"`
	Author          string `json:"author"`
	BaselineHash    string `json:"baseline_hash,omitempty"`
	ProbeHash       string `json:"probe_hash,omitempty"`
}

// ValidateBlackboardKind checks if kind is one of the 5 supported uncertainty types.
func ValidateBlackboardKind(k string) bool {
	switch strings.ToLower(strings.TrimSpace(k)) {
	case BBKindAnomaly, BBKindHypothesis, BBKindPreconditionNeed, BBKindDeferredEndpoint, BBKindEnvConstraint:
		return true
	}
	return false
}

// ValidateBlackboardState checks if state is a valid epistemic lifecycle state.
func ValidateBlackboardState(st string) bool {
	switch strings.ToLower(strings.TrimSpace(st)) {
	case BBStateTentative, BBStateCorroborated, BBStatePromoted, BBStateRefuted, BBStateQuarantined:
		return true
	}
	return false
}

// knownDecoyTokens lists documentation/RFC/honeypot canary strings highlighted in
// Gingerbread House / AgentMirror evaluations that must never be trusted as real findings.
var knownDecoyTokens = []string{
	"akiaiosfodnn7example",
	"wjalrxutnfemi/k7mdeng/bpxrficyexamplekey",
	"canarytokens.com",
	"thinkst-canary",
	"gingerbread-decoy",
	"honeypot-canary",
	"fake_secret_do_not_use",
}

// DetectDeceptionIndicators checks whether an observation or candidate finding exhibits
// static honeypot canary markers or identical baseline-vs-probe response hashes.
func DetectDeceptionIndicators(text, baselineHash, probeHash string) (quarantine bool, reason string) {
	bh := strings.TrimSpace(baselineHash)
	ph := strings.TrimSpace(probeHash)
	if bh != "" && ph != "" && strings.EqualFold(bh, ph) {
		return true, "differential baseline check failed: probe response hash is identical to benign baseline response hash"
	}
	low := strings.ToLower(text)
	for _, marker := range knownDecoyTokens {
		if strings.Contains(low, marker) {
			return true, fmt.Sprintf("matched known decoy/canary indicator %q (potential deception/honeypot artifact)", marker)
		}
	}
	return false, ""
}

// CreateBlackboardEntry inserts a new uncertainty entry into PostgreSQL, automatically
// applying the anti-deception quarantine gate when decoy markers are detected.
func (d *DB) CreateBlackboardEntry(in BlackboardPostInput) (BlackboardEntry, error) {
	in.Kind = strings.ToLower(strings.TrimSpace(in.Kind))
	if !ValidateBlackboardKind(in.Kind) {
		return BlackboardEntry{}, ErrBBInvalidKind
	}
	in.Topic = strings.TrimSpace(in.Topic)
	if in.Topic == "" {
		return BlackboardEntry{}, ErrBBEmptyTopic
	}
	in.Target = strings.TrimSpace(in.Target)
	in.Detail = strings.TrimSpace(in.Detail)
	in.PreconditionTag = strings.ToLower(strings.TrimSpace(in.PreconditionTag))
	in.EvidenceRef = strings.TrimSpace(in.EvidenceRef)
	in.Author = strings.TrimSpace(in.Author)
	if in.Author == "" {
		in.Author = "worker"
	}

	state := BBStateTentative
	var corrs []BlackboardCorroboration
	if q, reason := DetectDeceptionIndicators(in.Topic+" "+in.Detail+" "+in.EvidenceRef, in.BaselineHash, in.ProbeHash); q {
		state = BBStateQuarantined
		corrs = append(corrs, BlackboardCorroboration{
			Author:    "anti-deception-gate",
			Action:    "quarantine",
			Note:      reason,
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		})
	}
	corrBytes, _ := json.Marshal(corrs)

	var rec BlackboardEntry
	var corrRaw []byte
	err := d.QueryRow(`
INSERT INTO blackboard_entries (
    task_id, kind, epistemic_state, target, topic, detail, precondition_tag, evidence_ref, author, corroborations
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb)
RETURNING id, task_id, kind, epistemic_state, target, topic, detail, precondition_tag, evidence_ref, author, corroborations,
          to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
          to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')`,
		in.TaskID, in.Kind, state, in.Target, in.Topic, in.Detail, in.PreconditionTag, in.EvidenceRef, in.Author, string(corrBytes),
	).Scan(
		&rec.ID, &rec.TaskID, &rec.Kind, &rec.EpistemicState, &rec.Target, &rec.Topic, &rec.Detail,
		&rec.PreconditionTag, &rec.EvidenceRef, &rec.Author, &corrRaw, &rec.CreatedAt, &rec.UpdatedAt,
	)
	if err != nil {
		return BlackboardEntry{}, err
	}
	_ = json.Unmarshal(corrRaw, &rec.Corroborations)
	if rec.Corroborations == nil {
		rec.Corroborations = []BlackboardCorroboration{}
	}
	return rec, nil
}

// QueryBlackboardEntries searches a task's blackboard (and optionally inherited source tasks)
// by kind, epistemic_state, precondition_tag, or free-text query.
func (d *DB) QueryBlackboardEntries(taskIDs []int64, kind, state, preconditionTag, query string, limit int) ([]BlackboardEntry, error) {
	if len(taskIDs) == 0 {
		return []BlackboardEntry{}, nil
	}
	if limit <= 0 || limit > 100 {
		limit = 40
	}
	rows, err := d.Query(`
SELECT id, task_id, kind, epistemic_state, target, topic, detail, precondition_tag, evidence_ref, author, corroborations,
       to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
       to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
FROM blackboard_entries
WHERE task_id = ANY($1::bigint[])
  AND ($2 = '' OR kind = $2)
  AND ($3 = '' OR epistemic_state = $3)
  AND ($4 = '' OR precondition_tag = $4)
  AND ($5 = '' OR target ILIKE '%' || $5 || '%' OR topic ILIKE '%' || $5 || '%' OR detail ILIKE '%' || $5 || '%')
ORDER BY updated_at DESC, id DESC
LIMIT $6`,
		taskIDs,
		strings.ToLower(strings.TrimSpace(kind)),
		strings.ToLower(strings.TrimSpace(state)),
		strings.ToLower(strings.TrimSpace(preconditionTag)),
		strings.TrimSpace(query),
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []BlackboardEntry
	for rows.Next() {
		var rec BlackboardEntry
		var corrRaw []byte
		if err := rows.Scan(
			&rec.ID, &rec.TaskID, &rec.Kind, &rec.EpistemicState, &rec.Target, &rec.Topic, &rec.Detail,
			&rec.PreconditionTag, &rec.EvidenceRef, &rec.Author, &corrRaw, &rec.CreatedAt, &rec.UpdatedAt,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(corrRaw, &rec.Corroborations)
		if rec.Corroborations == nil {
			rec.Corroborations = []BlackboardCorroboration{}
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

// CorroborateBlackboardEntry appends an independent observation/proof/refutation to an existing
// blackboard entry and updates its epistemic state.
func (d *DB) CorroborateBlackboardEntry(id int64, action, newState, author, note, evidenceRef, baselineHash, probeHash string) (BlackboardEntry, error) {
	if !ValidateBlackboardState(newState) {
		return BlackboardEntry{}, ErrBBInvalidState
	}
	if q, reason := DetectDeceptionIndicators(note+" "+evidenceRef, baselineHash, probeHash); q {
		newState = BBStateQuarantined
		action = "quarantine"
		note = reason + " | original: " + note
	}
	c := BlackboardCorroboration{
		Author:      strings.TrimSpace(author),
		Action:      strings.TrimSpace(action),
		Note:        strings.TrimSpace(note),
		EvidenceRef: strings.TrimSpace(evidenceRef),
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
	}
	if c.Author == "" {
		c.Author = "worker"
	}
	cb, _ := json.Marshal([]BlackboardCorroboration{c})

	var rec BlackboardEntry
	var corrRaw []byte
	err := d.QueryRow(`
UPDATE blackboard_entries
SET epistemic_state = $2,
    corroborations = corroborations || $3::jsonb
WHERE id = $1
RETURNING id, task_id, kind, epistemic_state, target, topic, detail, precondition_tag, evidence_ref, author, corroborations,
          to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
          to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')`,
		id, strings.ToLower(strings.TrimSpace(newState)), string(cb),
	).Scan(
		&rec.ID, &rec.TaskID, &rec.Kind, &rec.EpistemicState, &rec.Target, &rec.Topic, &rec.Detail,
		&rec.PreconditionTag, &rec.EvidenceRef, &rec.Author, &corrRaw, &rec.CreatedAt, &rec.UpdatedAt,
	)
	if err != nil {
		return BlackboardEntry{}, err
	}
	_ = json.Unmarshal(corrRaw, &rec.Corroborations)
	return rec, nil
}

// MemoryBlackboard provides an in-memory thread-safe blackboard store used when
// PostgreSQL is not attached (e.g. unit tests) or as a fast runtime mirror.
type MemoryBlackboard struct {
	mu      sync.RWMutex
	nextID  int64
	entries []BlackboardEntry
}

func NewMemoryBlackboard() *MemoryBlackboard {
	return &MemoryBlackboard{nextID: 1}
}

func (m *MemoryBlackboard) Post(in BlackboardPostInput) (BlackboardEntry, error) {
	in.Kind = strings.ToLower(strings.TrimSpace(in.Kind))
	if !ValidateBlackboardKind(in.Kind) {
		return BlackboardEntry{}, ErrBBInvalidKind
	}
	in.Topic = strings.TrimSpace(in.Topic)
	if in.Topic == "" {
		return BlackboardEntry{}, ErrBBEmptyTopic
	}
	state := BBStateTentative
	corrs := []BlackboardCorroboration{}
	now := time.Now().UTC().Format(time.RFC3339)
	if q, reason := DetectDeceptionIndicators(in.Topic+" "+in.Detail+" "+in.EvidenceRef, in.BaselineHash, in.ProbeHash); q {
		state = BBStateQuarantined
		corrs = append(corrs, BlackboardCorroboration{
			Author:    "anti-deception-gate",
			Action:    "quarantine",
			Note:      reason,
			Timestamp: now,
		})
	}
	author := strings.TrimSpace(in.Author)
	if author == "" {
		author = "worker"
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	id := m.nextID
	m.nextID++
	entry := BlackboardEntry{
		ID:              id,
		TaskID:          in.TaskID,
		Kind:            in.Kind,
		EpistemicState:  state,
		Target:          strings.TrimSpace(in.Target),
		Topic:           in.Topic,
		Detail:          strings.TrimSpace(in.Detail),
		PreconditionTag: strings.ToLower(strings.TrimSpace(in.PreconditionTag)),
		EvidenceRef:     strings.TrimSpace(in.EvidenceRef),
		Author:          author,
		Corroborations:  corrs,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	m.entries = append(m.entries, entry)
	return entry, nil
}

func (m *MemoryBlackboard) Query(taskIDs []int64, kind, state, preconditionTag, query string, limit int) []BlackboardEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if limit <= 0 || limit > 100 {
		limit = 40
	}
	taskSet := map[int64]bool{}
	for _, tid := range taskIDs {
		taskSet[tid] = true
	}
	k := strings.ToLower(strings.TrimSpace(kind))
	st := strings.ToLower(strings.TrimSpace(state))
	pt := strings.ToLower(strings.TrimSpace(preconditionTag))
	q := strings.ToLower(strings.TrimSpace(query))

	var out []BlackboardEntry
	for i := len(m.entries) - 1; i >= 0; i-- {
		e := m.entries[i]
		if len(taskSet) > 0 && !taskSet[e.TaskID] {
			continue
		}
		if k != "" && e.Kind != k {
			continue
		}
		if st != "" && e.EpistemicState != st {
			continue
		}
		if pt != "" && e.PreconditionTag != pt {
			continue
		}
		if q != "" {
			hay := strings.ToLower(e.Target + " " + e.Topic + " " + e.Detail)
			if !strings.Contains(hay, q) {
				continue
			}
		}
		cp := e
		cp.Corroborations = append([]BlackboardCorroboration(nil), e.Corroborations...)
		out = append(out, cp)
		if len(out) >= limit {
			break
		}
	}
	return out
}

func (m *MemoryBlackboard) Corroborate(id int64, action, newState, author, note, evidenceRef, baselineHash, probeHash string) (BlackboardEntry, error) {
	if !ValidateBlackboardState(newState) {
		return BlackboardEntry{}, ErrBBInvalidState
	}
	if q, reason := DetectDeceptionIndicators(note+" "+evidenceRef, baselineHash, probeHash); q {
		newState = BBStateQuarantined
		action = "quarantine"
		note = reason + " | original: " + note
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.entries {
		if m.entries[i].ID == id {
			now := time.Now().UTC().Format(time.RFC3339)
			if strings.TrimSpace(author) == "" {
				author = "worker"
			}
			m.entries[i].EpistemicState = strings.ToLower(strings.TrimSpace(newState))
			m.entries[i].UpdatedAt = now
			m.entries[i].Corroborations = append(m.entries[i].Corroborations, BlackboardCorroboration{
				Author:      strings.TrimSpace(author),
				Action:      strings.TrimSpace(action),
				Note:        strings.TrimSpace(note),
				EvidenceRef: strings.TrimSpace(evidenceRef),
				Timestamp:   now,
			})
			cp := m.entries[i]
			cp.Corroborations = append([]BlackboardCorroboration(nil), m.entries[i].Corroborations...)
			return cp, nil
		}
	}
	return BlackboardEntry{}, ErrBBNotFound
}
