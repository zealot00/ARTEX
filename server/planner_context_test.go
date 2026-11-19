package server

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/guard"
)

func TestPlannerRuntimeContextAndInfraBaseline(t *testing.T) {
	baseDir := t.TempDir()
	taskDir := filepath.Join(baseDir, "tasks", "77")
	if err := os.MkdirAll(filepath.Join(taskDir, "repo"), 0o755); err != nil {
		t.Fatal(err)
	}
	javaCtrl := `@RestController
public class OrderController {
    @DeleteMapping("/api/orders/{id}")
    public String deleteOrder(Long id) {
        return "deleted " + id;
    }
}
`
	if err := os.WriteFile(filepath.Join(taskDir, "repo", "OrderController.java"), []byte(javaCtrl), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(taskDir, "repo", "pom.xml"), []byte("<project/>"), 0o644); err != nil {
		t.Fatal(err)
	}

	rules, err := guard.ParseFenceRules([]string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	g := guard.New()
	g.SetFence(true, rules)
	task := &Task{
		ID:                "77",
		ComplianceProfile: "mlps",
		ProdSafeMode:      true,
		FenceEnabled:      true,
		FenceRules:        []string{"127.0.0.1"},
		LateralGate:       true,
		LateralApproved:   false,
		Guard:             g,
	}
	s := &Server{
		m: &Manager{
			dir:   baseDir,
			tasks: map[string]*Task{"77": task},
		},
	}

	// 1) PlannerRuntimeContext should report guardrails, lateral gate warning, white-box source code, and PoC count.
	ctxText := s.buildPlannerRuntimeContext(77, taskDir)
	for _, want := range []string{
		"prod_safe_mode=true",
		"fence_enabled=true",
		"Lateral movement is GATED",
		"White-box source code detected",
		"repo/pom.xml",
		"run_infra_baseline",
	} {
		if !strings.Contains(ctxText, want) {
			t.Errorf("buildPlannerRuntimeContext missing %q:\n%s", want, ctxText)
		}
	}

	// 2) code_audit_auth_gaps + code_read_context
	gapRes, err := s.toolCodeAuditAuthGaps().Call(context.Background(), json.RawMessage(`{"task_id":"77","path":"repo"}`), nil)
	if err != nil || gapRes.IsError || !strings.Contains(resultText(gapRes), "/api/orders/{id}") {
		t.Fatalf("code_audit_auth_gaps failed: err=%v res=%+v", err, gapRes)
	}
	readRes, err := s.toolCodeReadContext().Call(context.Background(), json.RawMessage(`{"task_id":"77","file":"repo/OrderController.java","line":3,"radius":3}`), nil)
	if err != nil || readRes.IsError {
		t.Fatalf("code_read_context failed: err=%v res=%+v", err, readRes)
	}
	var readOut struct {
		Content string `json:"content"`
	}
	if err := json.Unmarshal([]byte(resultText(readRes)), &readOut); err != nil || !strings.Contains(readOut.Content, ">>    3 |") {
		t.Fatalf("code_read_context unexpected content: err=%v out=%+v", err, readOut)
	}

	// 3) run_infra_baseline port-to-PoC auto-matching against a local mock Redis server.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for i := 0; i < 2; i++ {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			buf := make([]byte, 256)
			_, _ = conn.Read(buf)
			_, _ = conn.Write([]byte("+PONG\r\nredis_version:7.2.4\r\n"))
			_ = conn.Close()
		}
	}()
	basePayload, _ := json.Marshal(map[string]any{
		"task_id": "77",
		"target":  ln.Addr().String(),
		"ports":   []int{6379},
	})
	baseRes, err := s.toolRunInfraBaseline().Call(context.Background(), basePayload, nil)
	if err != nil || baseRes.IsError {
		t.Fatalf("run_infra_baseline failed: err=%v res=%+v", err, baseRes)
	}
	btxt := resultText(baseRes)
	if !strings.Contains(btxt, "infra-redis-unauth-probe") || !strings.Contains(btxt, `"matched":true`) {
		t.Fatalf("expected run_infra_baseline to match Redis PoC, got: %s", btxt)
	}
}
