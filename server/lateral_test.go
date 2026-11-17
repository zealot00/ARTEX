package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func TestMatchesFootholdFinding(t *testing.T) {
	if !MatchesFootholdFinding(db.TaskEvent{VulnClass: "info_disclosure", Severity: "high"}, nil) {
		t.Fatal("high severity finding should qualify by default")
	}
	if !MatchesFootholdFinding(db.TaskEvent{VulnClass: "ssrf", Severity: "medium"}, nil) {
		t.Fatal("ssrf vuln class should qualify by default")
	}
	if MatchesFootholdFinding(db.TaskEvent{VulnClass: "missing_hsts", Severity: "low"}, nil) {
		t.Fatal("low severity missing_hsts should not trigger lateral movement")
	}

	// Explicit class filter
	if !MatchesFootholdFinding(db.TaskEvent{VulnClass: "Command_Injection", Severity: "high"}, []string{"command_injection", "rce"}) {
		t.Fatal("expected explicit class match")
	}
	if MatchesFootholdFinding(db.TaskEvent{VulnClass: "xss", Severity: "high"}, []string{"rce", "ssrf"}) {
		t.Fatal("xss must not match explicit rce/ssrf filter")
	}
}

func TestAPIKeyLateralApproveScope(t *testing.T) {
	s := &Server{
		jwtKey: []byte("01234567890123456789012345678901"),
		apiKeyAuthFn: func(raw string, _ time.Time) (*db.APIKey, error) {
			if raw == "artex_ak_ctrl" {
				return &db.APIKey{ID: 1, Name: "orchestrator", Scopes: []string{db.ScopeTasksControl}}, nil
			}
			return &db.APIKey{ID: 2, Name: "reader", Scopes: []string{db.ScopeTasksRead}}, nil
		},
	}
	h := s.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	reqForbidden := httptest.NewRequest(http.MethodPost, "/api/tasks/9/lateral/approve", nil)
	reqForbidden.Header.Set("X-API-Key", "artex_ak_reader")
	recForbidden := httptest.NewRecorder()
	h.ServeHTTP(recForbidden, reqForbidden)
	if recForbidden.Code != http.StatusForbidden {
		t.Fatalf("reader approve status=%d want 403", recForbidden.Code)
	}

	reqOK := httptest.NewRequest(http.MethodPost, "/api/tasks/9/lateral/approve", nil)
	reqOK.Header.Set("X-API-Key", "artex_ak_ctrl")
	recOK := httptest.NewRecorder()
	h.ServeHTTP(recOK, reqOK)
	if recOK.Code != http.StatusOK {
		t.Fatalf("control approve status=%d want 200", recOK.Code)
	}
}
