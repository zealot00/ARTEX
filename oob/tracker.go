package oob

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

const (
	maxTokensPerTask = 100
	maxHitsPerToken  = 100
	maxBodyPreview   = 2048
)

// Hit records one inbound HTTP callback observed on /oob/{token}.
type Hit struct {
	ID         int64             `json:"id"`
	ReceivedAt time.Time         `json:"received_at"`
	RemoteIP   string            `json:"remote_ip"`
	Method     string            `json:"method"`
	Path       string            `json:"path"`
	Query      string            `json:"query,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	Body       string            `json:"body,omitempty"`
}

// Token represents a task-scoped OOB callback endpoint token.
type Token struct {
	ID        string    `json:"token"`
	TaskID    int64     `json:"task_id"`
	Label     string    `json:"label,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	HitCount  int       `json:"hit_count"`
}

type tokenEntry struct {
	token Token
	hits  []Hit
}

// Tracker stores task-scoped OOB callback tokens and observed HTTP hits in memory.
type Tracker struct {
	mu      sync.RWMutex
	tokens  map[string]*tokenEntry
	byTask  map[int64][]string
	nextHit int64
}

// NewTracker constructs an empty OOB callback tracker.
func NewTracker() *Tracker {
	return &Tracker{
		tokens: make(map[string]*tokenEntry),
		byTask: make(map[int64][]string),
	}
}

// CreateToken allocates a new unpredictable callback token bound to taskID.
func (t *Tracker) CreateToken(taskID int64, label string) (*Token, error) {
	if taskID <= 0 {
		return nil, fmt.Errorf("invalid task_id")
	}
	var raw [12]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return nil, fmt.Errorf("generate oob token: %w", err)
	}
	id := hex.EncodeToString(raw[:])

	t.mu.Lock()
	defer t.mu.Unlock()

	existing := t.byTask[taskID]
	if len(existing) >= maxTokensPerTask {
		oldest := existing[0]
		t.byTask[taskID] = existing[1:]
		delete(t.tokens, oldest)
	}

	tok := Token{
		ID:        id,
		TaskID:    taskID,
		Label:     label,
		CreatedAt: time.Now().UTC(),
	}
	t.tokens[id] = &tokenEntry{token: tok}
	t.byTask[taskID] = append(t.byTask[taskID], id)
	copyTok := tok
	return &copyTok, nil
}

// RecordHit appends a callback hit if tokenID exists. Returns false when unknown.
func (t *Tracker) RecordHit(tokenID string, hit Hit) bool {
	if tokenID == "" {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	entry, ok := t.tokens[tokenID]
	if !ok {
		return false
	}
	t.nextHit++
	hit.ID = t.nextHit
	if hit.ReceivedAt.IsZero() {
		hit.ReceivedAt = time.Now().UTC()
	}
	if len(hit.Body) > maxBodyPreview {
		hit.Body = hit.Body[:maxBodyPreview] + "...(truncated)"
	}
	if len(entry.hits) >= maxHitsPerToken {
		entry.hits = entry.hits[1:]
	}
	entry.hits = append(entry.hits, hit)
	entry.token.HitCount++
	return true
}

// PollHits returns a snapshot of hits for tokenID, verifying taskID ownership when taskID > 0.
func (t *Tracker) PollHits(taskID int64, tokenID string) (*Token, []Hit, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	entry, ok := t.tokens[tokenID]
	if !ok {
		return nil, nil, false
	}
	if taskID > 0 && entry.token.TaskID != taskID {
		return nil, nil, false
	}
	tokCopy := entry.token
	hitsCopy := make([]Hit, len(entry.hits))
	copy(hitsCopy, entry.hits)
	return &tokCopy, hitsCopy, true
}

// ListTaskTokens returns metadata for all OOB tokens allocated under taskID.
func (t *Tracker) ListTaskTokens(taskID int64) []Token {
	t.mu.RLock()
	defer t.mu.RUnlock()

	ids := t.byTask[taskID]
	out := make([]Token, 0, len(ids))
	for _, id := range ids {
		if entry, ok := t.tokens[id]; ok {
			out = append(out, entry.token)
		}
	}
	return out
}

// DeleteTask removes all OOB tokens and recorded hits belonging to taskID.
func (t *Tracker) DeleteTask(taskID int64) {
	if taskID <= 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	for _, id := range t.byTask[taskID] {
		delete(t.tokens, id)
	}
	delete(t.byTask, taskID)
}
