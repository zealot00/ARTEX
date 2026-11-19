package server

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/guard"
)

func TestPocsAdminOnlyRoutes(t *testing.T) {
	s := &Server{jwtKey: []byte("0123456789abcdef0123456789abcdef")}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/pocs", s.listPocs)
	mux.HandleFunc("POST /api/pocs", s.createPoc)
	mux.HandleFunc("DELETE /api/pocs/{id}", s.deletePoc)
	h := s.requireAuth(mux)

	for _, tc := range []struct {
		method string
		path   string
	}{
		{"GET", "/api/pocs"},
		{"POST", "/api/pocs"},
		{"DELETE", "/api/pocs/1"},
	} {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != 401 {
			t.Fatalf("%s %s unauth: got %d, want 401", tc.method, tc.path, rec.Code)
		}
	}
}

func TestSearchPocsOfflineTemplatesAndFence(t *testing.T) {
	tmp := t.TempDir()
	tplDir := filepath.Join(tmp, "http", "cves", "2024")
	if err := os.MkdirAll(tplDir, 0o755); err != nil {
		t.Fatal(err)
	}
	tplFile := filepath.Join(tplDir, "CVE-2024-9999.yaml")
	if err := os.WriteFile(tplFile, []byte("id: CVE-2024-9999\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARTEX_NUCLEI_TEMPLATES_DIR", tmp)

	rules, err := guard.ParseFenceRules([]string{"10.10.0.0/16"})
	if err != nil {
		t.Fatal(err)
	}
	g := guard.New()
	g.SetFence(true, rules)
	task := &Task{ID: "99", FenceEnabled: true, Guard: g}
	m := &Manager{tasks: map[string]*Task{"99": task}}

	s := &Server{m: m}

	searchTool := s.toolSearchPocs()
	res, err := searchTool.Call(context.Background(), json.RawMessage(`{"query":"CVE-2024-9999"}`), nil)
	if err != nil || res.IsError {
		t.Fatalf("search_pocs failed: err=%v res=%+v", err, res)
	}
	if !strings.Contains(resultText(res), "http/cves/2024/CVE-2024-9999.yaml") {
		t.Fatalf("expected offline template in search_pocs output: %s", resultText(res))
	}

	runTool := s.toolRunPoc()
	// Out-of-scope target must be blocked by electronic fence before invoking nuclei.
	resBlocked, err := runTool.Call(context.Background(), json.RawMessage(`{"task_id":"99","target":"http://192.168.1.50:8080","template_path":"http/cves/2024/CVE-2024-9999.yaml"}`), nil)
	if err != nil {
		t.Fatalf("run_poc error: %v", err)
	}
	if !resBlocked.IsError || !strings.Contains(resultText(resBlocked), "electronic fence blocked") {
		t.Fatalf("expected electronic fence block, got: %+v", resBlocked)
	}

	// Path traversal in template_path must be rejected.
	resTrav, err := runTool.Call(context.Background(), json.RawMessage(`{"task_id":"99","target":"http://10.10.1.5:8080","template_path":"../../etc/passwd"}`), nil)
	if err != nil {
		t.Fatalf("run_poc traversal error: %v", err)
	}
	if !resTrav.IsError {
		t.Fatalf("expected path traversal rejection, got: %+v", resTrav)
	}

	// Inline custom python_script PoC execution under fence + OOB env injection.
	inlinePayload, _ := json.Marshal(map[string]any{
		"task_id":        "99",
		"target":         "http://10.10.1.5:8080",
		"inline_kind":    "python_script",
		"oob_token":      "tok123",
		"inline_content": "import os\nprint(os.environ.get('ARTEX_POC_TARGET'), os.environ.get('ARTEX_OOB_TOKEN'))\n",
	})
	resInline, err := runTool.Call(context.Background(), inlinePayload, nil)
	if err != nil || resInline.IsError {
		t.Fatalf("run_poc inline python_script failed: err=%v res=%+v", err, resInline)
	}
	txt := resultText(resInline)
	if !strings.Contains(txt, "http://10.10.1.5:8080 tok123") || !strings.Contains(txt, `"matched":true`) {
		t.Fatalf("unexpected inline PoC output: %s", txt)
	}
}

func TestDefaultInfraPocsCatalogAndRedisProbe(t *testing.T) {
	pocs := defaultIntranetPocs()
	if len(pocs) < 22 {
		t.Fatalf("expected at least 22 built-in intranet/infra PoCs, got %d", len(pocs))
	}
	seen := map[string]bool{}
	var redisScript string
	for _, p := range pocs {
		if p.Name == "" || strings.TrimSpace(p.Content) == "" {
			t.Fatalf("invalid default poc entry: %+v", p)
		}
		if seen[p.Name] {
			t.Fatalf("duplicate default poc name: %s", p.Name)
		}
		seen[p.Name] = true
		if p.Kind != db.PocKindNucleiYAML && p.Kind != db.PocKindPythonScript {
			t.Fatalf("invalid kind %q on %s", p.Kind, p.Name)
		}
		if p.Name == "infra-redis-unauth-probe" {
			redisScript = p.Content
		}
	}
	for _, required := range []string{
		"infra-samba-smb-null-signing",
		"infra-k8s-kubelet-unauth",
		"infra-k8s-etcd-unauth",
		"infra-k8s-dashboard-unauth",
		"infra-docker-registry-harbor-unauth",
		"infra-redis-unauth-probe",
		"infra-elasticsearch-unauth",
		"infra-jenkins-unauth-exposure",
		"infra-ldap-anonymous-bind",
		"infra-snmp-default-community",
	} {
		if !seen[required] {
			t.Fatalf("missing required infra PoC %q", required)
		}
	}

	// Execute the built-in Redis unauth probe against a local mock TCP listener.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 256)
		_, _ = conn.Read(buf)
		_, _ = conn.Write([]byte("+PONG\r\n# Server\r\nredis_version:7.2.4\r\nos:Linux\r\n"))
	}()

	task := &Task{ID: "101", Guard: guard.New()}
	s := &Server{m: &Manager{tasks: map[string]*Task{"101": task}}}
	runTool := s.toolRunPoc()
	payload, _ := json.Marshal(map[string]any{
		"task_id":        "101",
		"target":         ln.Addr().String(),
		"inline_kind":    "python_script",
		"inline_content": redisScript,
	})
	res, err := runTool.Call(context.Background(), payload, nil)
	if err != nil || res.IsError {
		t.Fatalf("redis probe failed: err=%v res=%+v", err, res)
	}
	txt := resultText(res)
	if !strings.Contains(txt, "CONFIRMED Redis unauthenticated access") || !strings.Contains(txt, "redis_version:7.2.4") {
		t.Fatalf("unexpected redis probe output: %s", txt)
	}
}
