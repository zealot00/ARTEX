package server

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCodeAuditServerToolsAndContainment(t *testing.T) {
	baseDir := t.TempDir()
	taskDir := filepath.Join(baseDir, "tasks", "66", "app")
	if err := os.MkdirAll(taskDir, 0o755); err != nil {
		t.Fatal(err)
	}
	pyCode := `from flask import Flask, request
app = Flask(__name__)

@app.route("/api/otp/send", methods=["POST"])
def send_otp():
    ticket = "t-123"
    return {"ok": True, "ticket": ticket}

def run_cmd(arg):
    import os
    return os.system("ping -c 1 " + arg)
`
	if err := os.WriteFile(filepath.Join(taskDir, "app.py"), []byte(pyCode), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(taskDir, "requirements.txt"), []byte("PyYAML==5.4.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	s := &Server{
		m: &Manager{
			dir:   baseDir,
			tasks: map[string]*Task{"66": {ID: "66"}},
		},
	}

	// Containment check: path traversal must fail.
	resEsc, _ := s.toolCodeMapEntrypoints().Call(context.Background(), json.RawMessage(`{"task_id":"66","path":"../../"}`), nil)
	if !resEsc.IsError {
		t.Fatalf("expected workspace escape rejection, got: %+v", resEsc)
	}

	// 1) Map entrypoints
	resMap, err := s.toolCodeMapEntrypoints().Call(context.Background(), json.RawMessage(`{"task_id":"66","path":"app"}`), nil)
	if err != nil || resMap.IsError || !strings.Contains(resultText(resMap), "/api/otp/send") {
		t.Fatalf("code_map_entrypoints failed: err=%v res=%+v", err, resMap)
	}

	// 2) Scan sinks
	resSink, err := s.toolCodeScanSinks().Call(context.Background(), json.RawMessage(`{"task_id":"66","path":"app"}`), nil)
	if err != nil || resSink.IsError {
		t.Fatalf("code_scan_sinks failed: err=%v res=%+v", err, resSink)
	}
	stxt := resultText(resSink)
	if !strings.Contains(stxt, "preauth-ticket-otp-leak") || !strings.Contains(stxt, "python-shell-exec") {
		t.Fatalf("expected ticket leak and shell exec sinks, got: %s", stxt)
	}

	// 3) Trace symbol
	resTrace, err := s.toolCodeTraceSymbol().Call(context.Background(), json.RawMessage(`{"task_id":"66","path":"app","symbol":"run_cmd"}`), nil)
	if err != nil || resTrace.IsError || !strings.Contains(resultText(resTrace), "run_cmd") {
		t.Fatalf("code_trace_symbol failed: err=%v res=%+v", err, resTrace)
	}

	// 4) Audit deps
	resDeps, err := s.toolCodeAuditDeps().Call(context.Background(), json.RawMessage(`{"task_id":"66","path":"app"}`), nil)
	if err != nil || resDeps.IsError || !strings.Contains(resultText(resDeps), "pyyaml") {
		t.Fatalf("code_audit_deps failed: err=%v res=%+v", err, resDeps)
	}
}
