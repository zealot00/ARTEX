package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func TestValidateFenceInput(t *testing.T) {
	enabled, rules, err := validateFenceInput(nil, []string{" 10.10.0.0/16 ", "*.corp.local", "10.10.0.0/16"})
	if err != nil {
		t.Fatalf("validateFenceInput: %v", err)
	}
	if !enabled || len(rules) != 2 {
		t.Fatalf("expected enabled=true with 2 deduped rules, got enabled=%v rules=%v", enabled, rules)
	}

	on := true
	if _, _, err := validateFenceInput(&on, nil); err == nil {
		t.Fatal("expected fence_enabled=true with empty rules to error")
	}
	if _, _, err := validateFenceInput(&on, []string{"ftp://bad.example"}); err == nil {
		t.Fatal("expected invalid fence rule to error")
	}
}

func TestAPIKeyFenceRouteScopes(t *testing.T) {
	s := &Server{
		jwtKey: []byte("01234567890123456789012345678901"),
		apiKeyAuthFn: func(raw string, _ time.Time) (*db.APIKey, error) {
			switch raw {
			case "artex_ak_read":
				return &db.APIKey{ID: 1, Name: "reader", Scopes: []string{db.ScopeTasksRead}}, nil
			case "artex_ak_create":
				return &db.APIKey{ID: 2, Name: "dispatcher", Scopes: []string{db.ScopeTasksCreate}}, nil
			default:
				return nil, db.ErrAPIKeyUnauthorized
			}
		},
	}
	h := s.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	call := func(method, path, key string) int {
		req := httptest.NewRequest(method, path, nil)
		req.Header.Set("X-API-Key", key)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	if code := call(http.MethodGet, "/api/tasks/5/fence", "artex_ak_read"); code != http.StatusOK {
		t.Fatalf("GET fence status=%d want 200", code)
	}
	if code := call(http.MethodPut, "/api/tasks/5/fence", "artex_ak_read"); code != http.StatusForbidden {
		t.Fatalf("PUT fence with reader key status=%d want 403", code)
	}
	if code := call(http.MethodPut, "/api/tasks/5/fence", "artex_ak_create"); code != http.StatusOK {
		t.Fatalf("PUT fence with creator key status=%d want 200", code)
	}
}
