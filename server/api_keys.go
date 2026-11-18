package server

import (
	"database/sql"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
)

func (s *Server) authenticateAPIKey(raw string) (*db.APIKey, error) {
	if s.apiKeyAuthFn != nil {
		return s.apiKeyAuthFn(raw, time.Now())
	}
	if s.m == nil || s.m.pg == nil {
		return nil, db.ErrAPIKeyUnauthorized
	}
	return s.m.pg.AuthenticateAPIKey(raw, time.Now())
}

// authorizeAPIKeyRoute maps HTTP method + path to the required API key scope.
// Routes outside the work-order allowlist return allowed=false (403 Forbidden),
// keeping administrative, LLM profile, workspace, tool, and auth endpoints off-limits
// to machine keys.
func authorizeAPIKeyRoute(method, path string) (scope string, allowed bool) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) < 2 || parts[0] != "api" {
		return "", false
	}
	rest := parts[1:]

	switch rest[0] {
	case "stats":
		if method == http.MethodGet && len(rest) == 1 {
			return db.ScopeTasksRead, true
		}
	case "report":
		if method == http.MethodGet && len(rest) == 1 {
			return db.ScopeFindingsRead, true
		}
	case "chat":
		if method == http.MethodPost && len(rest) == 1 {
			return db.ScopeChatWrite, true
		}
	case "tasks":
		return authorizeTaskAPIKeyRoute(method, rest[1:])
	case "exploration":
		return authorizeExplorationAPIKeyRoute(method, rest[1:])
	case "intercept":
		return authorizeInterceptAPIKeyRoute(method, rest[1:])
	}
	return "", false
}

func authorizeTaskAPIKeyRoute(method string, tail []string) (string, bool) {
	switch len(tail) {
	case 0:
		if method == http.MethodGet {
			return db.ScopeTasksRead, true
		}
		if method == http.MethodPost {
			return db.ScopeTasksCreate, true
		}
	case 1:
		if method == http.MethodGet {
			return db.ScopeTasksRead, true
		}
	case 2:
		if tail[0] == "control" && tail[1] == "batch" && method == http.MethodPost {
			return db.ScopeTasksControl, true
		}
		switch tail[1] {
		case "outcome", "workorder", "coverage", "coverage-graph", "scope", "goals", "constraints", "checks", "fence", "sessions":
			if method == http.MethodGet {
				return db.ScopeTasksRead, true
			}
			if method == http.MethodPost && (tail[1] == "scope" || tail[1] == "goals" || tail[1] == "constraints") {
				return db.ScopeTasksCreate, true
			}
			if method == http.MethodPut && tail[1] == "fence" {
				return db.ScopeTasksCreate, true
			}
		case "credentials":
			if method == http.MethodPost {
				return db.ScopeTasksCreate, true
			}
		case "control":
			if method == http.MethodPost {
				return db.ScopeTasksControl, true
			}
		case "target-pins":
			if method == http.MethodGet {
				return db.ScopeInterceptDecide, true
			}
		}
	case 3:
		if tail[1] == "sessions" && method == http.MethodDelete {
			return db.ScopeTasksControl, true
		}
		if tail[1] == "checks" && method == http.MethodPut {
			return db.ScopeTasksCreate, true
		}
		if tail[1] == "report" && tail[2] == "mlps" && method == http.MethodGet {
			return db.ScopeFindingsRead, true
		}
		if tail[1] == "lateral" && tail[2] == "approve" && method == http.MethodPost {
			return db.ScopeTasksControl, true
		}
		if tail[1] == "chat" && tail[2] == "status" && method == http.MethodGet {
			return db.ScopeTasksRead, true
		}
		if tail[1] == "chat" && tail[2] == "stop" && method == http.MethodPost {
			return db.ScopeTasksControl, true
		}
		if tail[1] == "intents" && tail[2] == "rerun-blocked" && method == http.MethodPost {
			return db.ScopeTasksControl, true
		}
	case 4:
		if tail[1] == "intents" && method == http.MethodPost {
			switch tail[3] {
			case "control", "rerun":
				return db.ScopeTasksControl, true
			case "messages":
				return db.ScopeChatWrite, true
			}
		}
	}
	return "", false
}

func authorizeExplorationAPIKeyRoute(method string, tail []string) (string, bool) {
	if method != http.MethodGet || len(tail) == 0 {
		return "", false
	}
	switch tail[0] {
	case "frontier", "intents", "graph", "nodes", "tokens":
		if len(tail) == 1 {
			return db.ScopeTasksRead, true
		}
	case "activity":
		if len(tail) == 1 || (len(tail) == 2 && (tail[1] == "history" || tail[1] == "stream" || tail[1] != "")) {
			return db.ScopeTasksRead, true
		}
	case "findings":
		if len(tail) == 1 {
			return db.ScopeFindingsRead, true
		}
		if len(tail) == 2 && (tail[1] == "groups" || tail[1] == "asset-tree" || tail[1] == "stats" || tail[1] == "export" || tail[1] != "") {
			return db.ScopeFindingsRead, true
		}
		if len(tail) == 3 && tail[2] == "lineage" {
			return db.ScopeFindingsRead, true
		}
	}
	return "", false
}

func authorizeInterceptAPIKeyRoute(method string, tail []string) (string, bool) {
	if len(tail) == 1 && tail[0] == "pending" && method == http.MethodGet {
		return db.ScopeInterceptDecide, true
	}
	if len(tail) == 2 && tail[0] == "pending" && method == http.MethodGet {
		return db.ScopeInterceptDecide, true
	}
	if len(tail) == 2 && tail[0] == "task" && method == http.MethodGet {
		return db.ScopeInterceptDecide, true
	}
	if len(tail) == 3 && tail[0] == "pending" && tail[2] == "decide" && method == http.MethodPost {
		return db.ScopeInterceptDecide, true
	}
	return "", false
}

func (s *Server) listAPIKeys(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdminJWT(w, r) {
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	keys, err := pg.ListAPIKeys()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{
		"keys":             keys,
		"available_scopes": db.AllAPIKeyScopes,
	})
}

func (s *Server) createAPIKey(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdminJWT(w, r) {
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var req struct {
		Name           string   `json:"name"`
		Scopes         []string `json:"scopes"`
		ExpiresInHours *int     `json:"expires_in_hours"`
	}
	if err := decode(w, r, &req); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	var expiresAt *time.Time
	if req.ExpiresInHours != nil {
		if *req.ExpiresInHours <= 0 {
			writeErr(w, 400, "expires_in_hours must be positive")
			return
		}
		t := time.Now().Add(time.Duration(*req.ExpiresInHours) * time.Hour)
		expiresAt = &t
	}
	key, secret, err := pg.CreateAPIKey(req.Name, req.Scopes, expiresAt)
	if err != nil {
		if errors.Is(err, db.ErrAPIKeyInvalidName) || errors.Is(err, db.ErrAPIKeyInvalidScope) {
			writeErr(w, 400, err.Error())
			return
		}
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 201, map[string]any{
		"key":    key,
		"secret": secret,
	})
}

func (s *Server) revokeAPIKey(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdminJWT(w, r) {
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "invalid api key id")
		return
	}
	revoked, err := pg.RevokeAPIKey(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if !revoked {
		writeErr(w, 404, "api key not found or already revoked")
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// taskWorkOrder returns an aggregated status snapshot for external polling agents.
func (s *Server) taskWorkOrder(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	status := s.resolvedTaskStatus(t)
	dto := taskDTO(t, status)
	if metrics, err := s.m.PG().TaskListMetricsAll(); err == nil {
		s.applyTaskMetrics(&dto, t, metrics[t.ExpID])
	}
	if archiveBlockers, err := s.m.PG().TaskArchiveBlockers(); err == nil {
		applyTaskArchiveBlocker(&dto, archiveBlockers)
	}

	taskID, _ := strconv.ParseInt(t.ID, 10, 64)
	var outcome any
	if o, err := s.m.PG().TaskOutcome(r.Context(), taskID); err == nil {
		outcome = o
	} else if !errors.Is(err, sql.ErrNoRows) {
		writeErr(w, 500, "outcome query failed")
		return
	}
	pending, pendingTotal, err := s.m.PG().ListTaskInterceptsPage(t.ID, 1, 50, db.InterceptApprovalFilter{Status: "pending"})
	if err != nil {
		pending = nil
		pendingTotal = 0
	}
	if pending == nil {
		pending = []db.InterceptApprovalRow{}
	}
	writeJSON(w, 200, map[string]any{
		"task":                   dto,
		"terminal":               isTerminalStatus(status),
		"outcome":                outcome,
		"pending_approvals":      pending,
		"pending_approval_count": pendingTotal,
	})
}
