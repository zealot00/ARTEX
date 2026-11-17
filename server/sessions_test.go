package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/sessions"
)

func TestTaskSessionsRouteAuthScopes(t *testing.T) {
	s := &Server{
		jwtKey:  []byte("01234567890123456789012345678901"),
		sessMgr: sessions.NewManager(),
		apiKeyAuthFn: func(raw string, _ time.Time) (*db.APIKey, error) {
			if raw == "artex_ak_reader" {
				return &db.APIKey{ID: 1, Name: "reader", Scopes: []string{db.ScopeTasksRead}}, nil
			}
			return nil, db.ErrAPIKeyUnauthorized
		},
	}
	h := s.Handler()

	// Reader API key cannot DELETE a session (requires tasks:control -> 403).
	req := httptest.NewRequest(http.MethodDelete, "/api/tasks/1/sessions/sess-123", nil)
	req.Header.Set("X-API-Key", "artex_ak_reader")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("DELETE session with reader key: got %d, want 403", rec.Code)
	}
}
