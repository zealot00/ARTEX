package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWorkspaceRejectsSymlinkEscape(t *testing.T) {
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(secret, []byte("top-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Symlink(secret, filepath.Join(dir, "leak.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "escape_dir")); err != nil {
		t.Fatal(err)
	}
	s := &Server{m: &Manager{dir: dir}}

	if _, ok := s.wsResolve("leak.txt"); ok {
		t.Fatal("wsResolve allowed symlink pointing outside workspace")
	}
	if _, ok := s.wsResolve("escape_dir/new.txt"); ok {
		t.Fatal("wsResolve allowed write path through symlinked directory")
	}
	if _, ok := s.wsResolveDelete("escape_dir/secret.txt"); ok {
		t.Fatal("wsResolveDelete allowed delete inside symlinked external directory")
	}
	// Deleting the symlink entry itself (without following it) stays allowed.
	if got, ok := s.wsResolveDelete("leak.txt"); !ok || !strings.HasSuffix(got, string(os.PathSeparator)+"leak.txt") {
		t.Fatalf("wsResolveDelete(leak.txt) = (%q, %v), want allowed leaf inside workspace", got, ok)
	}
	// Ordinary nested non-existent path inside workspace resolves cleanly.
	if got, ok := s.wsResolve("tasks/1/out.txt"); !ok || !strings.HasSuffix(got, filepath.Join("tasks", "1", "out.txt")) {
		t.Fatalf("wsResolve(tasks/1/out.txt) = (%q, %v)", got, ok)
	}
}

func TestCORSAllowsAuthHeaderAndPatch(t *testing.T) {
	h := cors(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodOptions, "/api/tasks/1", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
	methods := rec.Header().Get("Access-Control-Allow-Methods")
	if !strings.Contains(methods, "PATCH") {
		t.Fatalf("Access-Control-Allow-Methods = %q, want PATCH", methods)
	}
	headers := rec.Header().Get("Access-Control-Allow-Headers")
	if !strings.Contains(headers, "Authorization") {
		t.Fatalf("Access-Control-Allow-Headers = %q, want Authorization", headers)
	}
}
