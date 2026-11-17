package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/wordlists"
)

func TestWordlistEndpointsRejectAPIKeyAndRequireAdminJWT(t *testing.T) {
	s := &Server{
		jwtKey: []byte("01234567890123456789012345678901"),
		apiKeyAuthFn: func(raw string, now time.Time) (*db.APIKey, error) {
			if raw == "artex_ak_valid" {
				return &db.APIKey{
					ID:     1,
					Name:   "ci",
					Scopes: db.AllAPIKeyScopes,
				}, nil
			}
			return nil, db.ErrAPIKeyUnauthorized
		},
	}
	h := s.Handler()

	for _, tc := range []struct {
		method string
		path   string
	}{
		{"GET", "/api/wordlists"},
		{"POST", "/api/wordlists"},
		{"DELETE", "/api/wordlists/1"},
	} {
		// Unauthenticated -> 401
		req := httptest.NewRequest(tc.method, tc.path, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s unauth: got %d, want 401", tc.method, tc.path, rec.Code)
		}

		// Scoped API Key -> 403 (even with all scopes)
		req = httptest.NewRequest(tc.method, tc.path, nil)
		req.Header.Set("Authorization", "Bearer artex_ak_valid")
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s %s api-key: got %d, want 403", tc.method, tc.path, rec.Code)
		}
	}

	// Admin JWT passes requireAdminJWT and hits DB-unavailable 503 (since s.m.pg is nil in unit test)
	tok, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatalf("signJWT: %v", err)
	}
	req := httptest.NewRequest("GET", "/api/wordlists", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET /api/wordlists admin JWT: got %d, want 503", rec.Code)
	}
}

func TestValidateCredentialAuditAndProdSafeCap(t *testing.T) {
	p := credentialAuditRequest{
		TaskID:   "1",
		Target:   "10.10.10.5",
		Service:  "SSH",
		Username: "root",
		PassList: "top100",
		Threads:  16,
	}
	if err := validateAndNormalizeAuditRequest(&p, true); err != nil {
		t.Fatalf("valid request failed: %v", err)
	}
	if p.Service != "ssh" || p.Threads != 4 {
		t.Fatalf("expected service=ssh and prodSafe threads=4, got service=%q threads=%d", p.Service, p.Threads)
	}

	badTarget := p
	badTarget.Target = "10.10.10.5; id"
	if err := validateAndNormalizeAuditRequest(&badTarget, false); err == nil {
		t.Fatalf("expected shell injection target to fail")
	}

	badSvc := p
	badSvc.Service = "bash"
	if err := validateAndNormalizeAuditRequest(&badSvc, false); err == nil {
		t.Fatalf("expected unsupported service to fail")
	}
}

func TestExecuteHydraAuditMasksPasswordsAndCleansTempFiles(t *testing.T) {
	keyDir := t.TempDir()
	vault, err := wordlists.NewVault(keyDir)
	if err != nil {
		t.Fatalf("NewVault: %v", err)
	}
	if _, _, err := vault.Save(7, []string{"Hunter2Secret!"}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	workTmp, err := os.MkdirTemp("", "artex-audit-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	passPath, _, err := vault.MaterializeTemp(7, workTmp, "passes")
	if err != nil {
		t.Fatalf("MaterializeTemp: %v", err)
	}

	fakeHydra := filepath.Join(t.TempDir(), "hydra")
	script := "#!/bin/sh\necho \"[22][ssh] host: 10.10.10.5   login: admin   password: $(cat " + passPath + ")\"\n"
	if err := os.WriteFile(fakeHydra, []byte(script), 0o755); err != nil {
		t.Fatalf("WriteFile fake hydra: %v", err)
	}

	req := credentialAuditRequest{
		TaskID:   "1",
		Target:   "10.10.10.5",
		Service:  "ssh",
		Port:     22,
		Username: "admin",
		Threads:  4,
	}
	args := buildHydraArgs(req, "", passPath, "")
	res, err := executeHydraAudit(context.Background(), fakeHydra, args, req, true)
	os.RemoveAll(workTmp)
	if err != nil {
		t.Fatalf("executeHydraAudit: %v", err)
	}

	rawJSON, _ := json.Marshal(res)
	out := string(rawJSON)
	if strings.Contains(out, "Hunter2Secret!") {
		t.Fatalf("tool output leaked plaintext password: %s", out)
	}
	wantMask := wordlists.MaskSecret("Hunter2Secret!")
	if !strings.Contains(out, wantMask) {
		t.Fatalf("expected masked password %q in output, got: %s", wantMask, out)
	}
}

func TestValidatePasswordSprayAndExecuteNxcSpray(t *testing.T) {
	p := passwordSprayRequest{
		TaskID:       "1",
		Target:       "10.10.0.10",
		Protocol:     "SMB",
		Domain:       "CORP",
		UserList:     "ad-users",
		PassList:     "seasonal",
		MaxPasswords: 10,
		DelaySeconds: 1,
	}
	if err := validateAndNormalizeSprayRequest(&p, true); err != nil {
		t.Fatalf("valid spray failed: %v", err)
	}
	if p.Protocol != "smb" || p.MaxPasswords != 1 || p.DelaySeconds != 2 {
		t.Fatalf("expected prodSafe caps max=1 delay=2, got proto=%q max=%d delay=%d", p.Protocol, p.MaxPasswords, p.DelaySeconds)
	}

	fakeNxc := filepath.Join(t.TempDir(), "nxc")
	script := "#!/bin/sh\necho 'SMB 10.10.0.10 445 DC01 [+] CORP\\alice:Summer2026! (Pwn3d!)'\n"
	if err := os.WriteFile(fakeNxc, []byte(script), 0o755); err != nil {
		t.Fatalf("WriteFile fake nxc: %v", err)
	}

	res, err := executeNxcSpray(context.Background(), fakeNxc, p, "alice", []string{"Summer2026!"}, 5, true)
	if err != nil {
		t.Fatalf("executeNxcSpray: %v", err)
	}
	rawJSON, _ := json.Marshal(res)
	out := string(rawJSON)
	if strings.Contains(out, "Summer2026!") {
		t.Fatalf("spray output leaked plaintext password: %s", out)
	}
	wantMask := wordlists.MaskSecret("Summer2026!")
	if !strings.Contains(out, wantMask) {
		t.Fatalf("expected masked password %q in spray output, got: %s", wantMask, out)
	}
}
