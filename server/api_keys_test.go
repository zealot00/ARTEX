package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func TestAPIKeyAuthScopesAndAdminIsolation(t *testing.T) {
	s := &Server{
		jwtKey: []byte("01234567890123456789012345678901"),
		apiKeyAuthFn: func(raw string, _ time.Time) (*db.APIKey, error) {
			switch raw {
			case "artex_ak_reader":
				return &db.APIKey{ID: 1, Name: "workorder-reader", Scopes: []string{db.ScopeTasksRead, db.ScopeFindingsRead}}, nil
			case "artex_ak_creator":
				return &db.APIKey{ID: 2, Name: "soar-dispatcher", Scopes: []string{db.ScopeTasksCreate}}, nil
			case "artex_ak_decider":
				return &db.APIKey{ID: 3, Name: "gate-bot", Scopes: []string{db.ScopeInterceptDecide}}, nil
			default:
				return nil, db.ErrAPIKeyUnauthorized
			}
		},
	}

	var gotApprover string
	protected := s.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotApprover = s.approver(r)
		w.WriteHeader(http.StatusOK)
	}))

	call := func(method, path, headerName, tok string) int {
		t.Helper()
		req := httptest.NewRequest(method, path, nil)
		if tok != "" {
			req.Header.Set(headerName, tok)
		}
		rec := httptest.NewRecorder()
		protected.ServeHTTP(rec, req)
		return rec.Code
	}

	// Unauthenticated or unknown API key -> 401
	if code := call(http.MethodGet, "/api/tasks", "Authorization", ""); code != http.StatusUnauthorized {
		t.Fatalf("missing token status=%d want 401", code)
	}
	if code := call(http.MethodGet, "/api/tasks", "X-API-Key", "artex_ak_revoked"); code != http.StatusUnauthorized {
		t.Fatalf("revoked key status=%d want 401", code)
	}

	// Reader key via X-API-Key & Authorization: Bearer
	if code := call(http.MethodGet, "/api/tasks/12/workorder", "X-API-Key", "artex_ak_reader"); code != http.StatusOK {
		t.Fatalf("reader workorder status=%d want 200", code)
	}
	if gotApprover != "apikey:workorder-reader" {
		t.Fatalf("approver=%q want apikey:workorder-reader", gotApprover)
	}
	if code := call(http.MethodGet, "/api/report?task=12", "Authorization", "Bearer artex_ak_reader"); code != http.StatusOK {
		t.Fatalf("reader report status=%d want 200", code)
	}
	if code := call(http.MethodGet, "/api/exploration/activity/stream?task=12", "X-API-Key", "artex_ak_reader"); code != http.StatusOK {
		t.Fatalf("reader stream status=%d want 200", code)
	}

	// Missing scope -> 403
	if code := call(http.MethodPost, "/api/tasks", "X-API-Key", "artex_ak_reader"); code != http.StatusForbidden {
		t.Fatalf("reader create task status=%d want 403", code)
	}
	if code := call(http.MethodPost, "/api/tasks", "X-API-Key", "artex_ak_creator"); code != http.StatusOK {
		t.Fatalf("creator create task status=%d want 200", code)
	}
	if code := call(http.MethodPost, "/api/tasks/1/control", "X-API-Key", "artex_ak_creator"); code != http.StatusForbidden {
		t.Fatalf("creator control task status=%d want 403", code)
	}
	if code := call(http.MethodPost, "/api/intercept/pending/9/decide", "X-API-Key", "artex_ak_decider"); code != http.StatusOK {
		t.Fatalf("decider decide status=%d want 200", code)
	}
	if code := call(http.MethodGet, "/api/intercept/pending", "X-API-Key", "artex_ak_decider"); code != http.StatusOK {
		t.Fatalf("decider list pending status=%d want 200", code)
	}
	if code := call(http.MethodPost, "/api/chat", "X-API-Key", "artex_ak_reader"); code != http.StatusForbidden {
		t.Fatalf("reader chat status=%d want 403", code)
	}

	// Admin/configuration endpoints are ALWAYS forbidden for any API key (403)
	for _, tc := range []struct {
		method, path string
	}{
		{http.MethodGet, "/api/llm"},
		{http.MethodPost, "/api/llm/profiles"},
		{http.MethodPut, "/api/settings"},
		{http.MethodPost, "/api/tools/custom"},
		{http.MethodGet, "/api/workspace/list"},
		{http.MethodGet, "/api/api-keys"},
		{http.MethodPost, "/api/api-keys"},
		{http.MethodDelete, "/api/tasks/1"},
		{http.MethodGet, "/api/tasks/1/credentials"},
	} {
		for _, tok := range []string{"artex_ak_reader", "artex_ak_creator", "artex_ak_decider"} {
			if code := call(tc.method, tc.path, "X-API-Key", tok); code != http.StatusForbidden {
				t.Fatalf("%s %s with %s: status=%d want 403", tc.method, tc.path, tok, code)
			}
		}
	}

	// Admin JWT keeps access to admin routes
	jwtTok, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	if code := call(http.MethodGet, "/api/api-keys", "Authorization", "Bearer "+jwtTok); code != http.StatusOK {
		t.Fatalf("admin JWT api-keys status=%d want 200", code)
	}
	if gotApprover != "ARTEX" {
		t.Fatalf("JWT approver=%q want ARTEX", gotApprover)
	}
}

func TestAPIKeyMgmtRejectsAPIKeyDirectHandlerCall(t *testing.T) {
	s := &Server{jwtKey: []byte("01234567890123456789012345678901")}
	req := httptest.NewRequest(http.MethodGet, "/api/api-keys", nil)
	req = req.WithContext(withAuthIdentity(req.Context(), AuthIdentity{
		Kind:     "api_key",
		Subject:  "apikey:bot",
		APIKeyID: 1,
		Scopes:   map[string]bool{db.ScopeTasksRead: true},
	}))
	rec := httptest.NewRecorder()
	s.listAPIKeys(rec, req)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "admin JWT") {
		t.Fatalf("expected 403 admin JWT error, got %d body=%s", rec.Code, rec.Body.String())
	}
}
