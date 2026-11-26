package server

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	actool "github.com/Autumn-27/norma/tool"
)

const (
	LeaseModeSharedRead      = "shared_read"
	LeaseModeExclusiveMutate = "exclusive_mutate"
	defaultLeaseTTL          = 180 * time.Second
	maxLeaseTTL              = 600 * time.Second
)

// ResourceLease tracks an active worker claim over a shared session, account, or endpoint
// to prevent concurrent workers from corrupting shared auth state or triggering lockouts.
type ResourceLease struct {
	TaskID      string    `json:"task_id"`
	ResourceKey string    `json:"resource_key"` // e.g. "cred:admin", "session:sess-1", "host:10.10.1.5:8080"
	Mode        string    `json:"mode"`         // "shared_read" | "exclusive_mutate"
	Holder      string    `json:"holder"`       // e.g. "intent#12" or worker label
	Purpose     string    `json:"purpose"`
	AcquiredAt  time.Time `json:"acquired_at"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// ResourceLeaseManager coordinates concurrent worker access to shared accounts, sessions, and rate-limited hosts.
type ResourceLeaseManager struct {
	mu     sync.Mutex
	leases []ResourceLease
}

var globalLeaseMgr = &ResourceLeaseManager{}

func (m *ResourceLeaseManager) sweepExpiredLocked(now time.Time) {
	kept := m.leases[:0]
	for _, l := range m.leases {
		if now.Before(l.ExpiresAt) {
			kept = append(kept, l)
		}
	}
	m.leases = kept
}

// Acquire attempts to acquire a shared_read or exclusive_mutate lease on (taskID, resourceKey).
// Conflict rules:
// - An existing exclusive_mutate lease by a DIFFERENT holder blocks both shared_read and exclusive_mutate.
// - An existing shared_read lease by a DIFFERENT holder blocks exclusive_mutate, but allows another shared_read.
// - Same holder re-acquiring updates the mode/TTL idempotently.
func (m *ResourceLeaseManager) Acquire(taskID, resourceKey, mode, holder, purpose string, ttl time.Duration) (ResourceLease, bool, string) {
	taskID = strings.TrimSpace(taskID)
	resourceKey = strings.ToLower(strings.TrimSpace(resourceKey))
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode != LeaseModeSharedRead && mode != LeaseModeExclusiveMutate {
		mode = LeaseModeExclusiveMutate
	}
	holder = strings.TrimSpace(holder)
	if holder == "" {
		holder = "worker"
	}
	if ttl <= 0 {
		ttl = defaultLeaseTTL
	}
	if ttl > maxLeaseTTL {
		ttl = maxLeaseTTL
	}

	now := time.Now().UTC()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sweepExpiredLocked(now)

	for _, l := range m.leases {
		if l.TaskID != taskID || l.ResourceKey != resourceKey {
			continue
		}
		if l.Holder == holder {
			continue
		}
		if l.Mode == LeaseModeExclusiveMutate {
			return l, false, fmt.Sprintf("resource %q is currently locked in exclusive_mutate mode by %s (%s) until %s",
				resourceKey, l.Holder, l.Purpose, l.ExpiresAt.Format(time.RFC3339))
		}
		if mode == LeaseModeExclusiveMutate && l.Mode == LeaseModeSharedRead {
			return l, false, fmt.Sprintf("cannot acquire exclusive_mutate on %q while %s holds a shared_read lease (%s)",
				resourceKey, l.Holder, l.Purpose)
		}
	}

	lease := ResourceLease{
		TaskID:      taskID,
		ResourceKey: resourceKey,
		Mode:        mode,
		Holder:      holder,
		Purpose:     strings.TrimSpace(purpose),
		AcquiredAt:  now,
		ExpiresAt:   now.Add(ttl),
	}
	// Replace existing lease by same holder on same resource if present.
	for i := range m.leases {
		if m.leases[i].TaskID == taskID && m.leases[i].ResourceKey == resourceKey && m.leases[i].Holder == holder {
			m.leases[i] = lease
			return lease, true, ""
		}
	}
	m.leases = append(m.leases, lease)
	return lease, true, ""
}

// Release removes a lease held by holder on (taskID, resourceKey).
func (m *ResourceLeaseManager) Release(taskID, resourceKey, holder string) bool {
	taskID = strings.TrimSpace(taskID)
	resourceKey = strings.ToLower(strings.TrimSpace(resourceKey))
	holder = strings.TrimSpace(holder)

	m.mu.Lock()
	defer m.mu.Unlock()
	m.sweepExpiredLocked(time.Now().UTC())

	removed := false
	kept := m.leases[:0]
	for _, l := range m.leases {
		if l.TaskID == taskID && l.ResourceKey == resourceKey && (holder == "" || l.Holder == holder) {
			removed = true
			continue
		}
		kept = append(kept, l)
	}
	m.leases = kept
	return removed
}

// List returns active leases for taskID.
func (m *ResourceLeaseManager) List(taskID string) []ResourceLease {
	taskID = strings.TrimSpace(taskID)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sweepExpiredLocked(time.Now().UTC())

	var out []ResourceLease
	for _, l := range m.leases {
		if l.TaskID == taskID {
			out = append(out, l)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].ResourceKey < out[j].ResourceKey
	})
	return out
}

func (s *Server) toolResourceLeaseAcquire() actool.CoreTool {
	return wrTool(
		"resource_lease_acquire",
		"Concurrent worker resource & session coordinator: acquires a shared_read or exclusive_mutate lease on a shared account, session, or rate-sensitive host (e.g. 'cred:admin', 'session:sess-1', 'host:10.10.1.5:8080') before performing state-mutating operations (password spray, logout/password-reset, race_probe, session reconfiguration) so concurrent workers do not invalidate each other's sessions.",
		objSchema(map[string]any{
			"task_id":      strParam("Task ID (numeric string)"),
			"resource_key": strParam("Normalized resource identifier (e.g. 'cred:testuser', 'session:s1', 'host:portal.corp.local')"),
			"mode":         strParam("Lease mode: 'exclusive_mutate' (default, blocks concurrent access) or 'shared_read'"),
			"holder":       strParam("Caller identifier (e.g. 'intent#42' or worker role)"),
			"purpose":      strParam("Short description of the operation (e.g. 'testing password reset flow on testuser')"),
			"ttl_seconds":  map[string]any{"type": "integer", "description": "Lease duration in seconds (default 180, max 600)"},
		}, "task_id", "resource_key", "holder"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var p struct {
				TaskID      string `json:"task_id"`
				ResourceKey string `json:"resource_key"`
				Mode        string `json:"mode"`
				Holder      string `json:"holder"`
				Purpose     string `json:"purpose"`
				TTLSeconds  int    `json:"ttl_seconds"`
			}
			if err := json.Unmarshal(in, &p); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if strings.TrimSpace(p.TaskID) == "" || strings.TrimSpace(p.ResourceKey) == "" {
				return actool.Errorf("task_id and resource_key are required"), nil
			}
			ttl := time.Duration(p.TTLSeconds) * time.Second
			lease, ok, conflictReason := globalLeaseMgr.Acquire(p.TaskID, p.ResourceKey, p.Mode, p.Holder, p.Purpose, ttl)
			if !ok {
				return jsonResult(map[string]any{
					"acquired":        false,
					"conflict_reason": conflictReason,
					"blocking_lease":  lease,
				})
			}
			return jsonResult(map[string]any{
				"acquired": true,
				"lease":    lease,
			})
		},
	)
}

func (s *Server) toolResourceLeaseRelease() actool.CoreTool {
	return wrTool(
		"resource_lease_release",
		"Releases a previously acquired resource/session lease once the state-mutating or rate-sensitive operation finishes.",
		objSchema(map[string]any{
			"task_id":      strParam("Task ID (numeric string)"),
			"resource_key": strParam("Resource identifier to release"),
			"holder":       strParam("Caller identifier that acquired the lease"),
		}, "task_id", "resource_key"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var p struct {
				TaskID      string `json:"task_id"`
				ResourceKey string `json:"resource_key"`
				Holder      string `json:"holder"`
			}
			if err := json.Unmarshal(in, &p); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			released := globalLeaseMgr.Release(p.TaskID, p.ResourceKey, p.Holder)
			return jsonResult(map[string]any{
				"released":     released,
				"resource_key": p.ResourceKey,
			})
		},
	)
}
