package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/guard"
)

func TestFocusedPersistentSolverEscalationAndPruning(t *testing.T) {
	task := &Task{ID: "199"}
	s := &Server{m: &Manager{tasks: map[string]*Task{"199": task}}}

	statusTool := s.toolSolverStatus()
	pruneTool := s.toolSolverPruneMechanism()
	escTool := s.toolSolverEscalate()

	// 1. Initial tier is L1_BASELINE.
	r0, err := statusTool.Call(context.Background(), json.RawMessage(`{"task_id":"199"}`), nil)
	if err != nil || r0.IsError || !strings.Contains(resultText(r0), `"L1_BASELINE"`) {
		t.Fatalf("expected initial L1_BASELINE, got err=%v res=%s", err, resultText(r0))
	}

	// 2. Prune two distinct mechanisms at L1 -> auto-escalates to L2_DEEP_BIZ_PROTO.
	r1, err := pruneTool.Call(context.Background(), json.RawMessage(`{
		"task_id": "199",
		"target": "http://10.10.1.5:8080/login",
		"mechanism": "default_creds",
		"reason": "Account lockout triggered after 3 failures",
		"evidence_ref": "traffic#101"
	}`), nil)
	if err != nil || r1.IsError || !strings.Contains(resultText(r1), `"auto_escalated":false`) {
		t.Fatalf("expected first prune not to auto-escalate yet: %s", resultText(r1))
	}

	r2, err := pruneTool.Call(context.Background(), json.RawMessage(`{
		"task_id": "199",
		"target": "http://10.10.1.5:8080/login",
		"mechanism": "sqli_error_based",
		"reason": "Parameterized query confirmed",
		"evidence_ref": "traffic#105"
	}`), nil)
	if err != nil || r2.IsError || !strings.Contains(resultText(r2), `"auto_escalated":true`) || !strings.Contains(resultText(r2), `"L2_DEEP_BIZ_PROTO"`) {
		t.Fatalf("expected second prune at L1 to auto-escalate to L2_DEEP_BIZ_PROTO: %s", resultText(r2))
	}

	// 3. Explicit escalation to L4_TECHNIQUE_SYNTHESIS and L5_ADJACENT_PIVOT.
	r4, err := escTool.Call(context.Background(), json.RawMessage(`{
		"task_id": "199",
		"target_tier": 4,
		"reason": "Custom signing protocol requires synthesized Python script"
	}`), nil)
	if err != nil || r4.IsError || !strings.Contains(resultText(r4), `"L4_TECHNIQUE_SYNTHESIS"`) {
		t.Fatalf("expected L4_TECHNIQUE_SYNTHESIS, got: %s", resultText(r4))
	}

	r5, err := escTool.Call(context.Background(), json.RawMessage(`{
		"task_id": "199",
		"target_tier": 5,
		"reason": "Direct perimeter hardened; pivot via adjacent Redis/config center"
	}`), nil)
	if err != nil || r5.IsError || !strings.Contains(resultText(r5), `"L5_ADJACENT_PIVOT"`) {
		t.Fatalf("expected L5_ADJACENT_PIVOT, got: %s", resultText(r5))
	}

	// 4. Verify PlannerRuntimeContext surfaces the active solver tier and pruned mechanisms.
	ctxText := s.buildPlannerRuntimeContext(199, t.TempDir())
	for _, want := range []string{
		"Focused Persistent Solver ('唯一求解'): stage=L5_ADJACENT_PIVOT (5/5)",
		"default_creds@http://10.10.1.5:8080/login",
		"Anti-premature-stop rule",
	} {
		if !strings.Contains(ctxText, want) {
			t.Fatalf("expected PlannerRuntimeContext to contain %q, got:\n%s", want, ctxText)
		}
	}
}

func TestDispatcherCommitGateDecisions(t *testing.T) {
	s := &Server{}
	gateTool := s.toolVerifyCandidateFinding()

	// 1. Static unexecuted lead -> downgraded to blackboard hypothesis.
	rStatic, err := gateTool.Call(context.Background(), json.RawMessage(`{
		"task_id": "200",
		"target": "src/AuthController.java:42",
		"title": "Potential SQLi in legacy export",
		"proof_basis": "static-analysis-unexecuted",
		"evidence_ref": "src/AuthController.java:42"
	}`), nil)
	if err != nil || rStatic.IsError || !strings.Contains(resultText(rStatic), `"downgrade_to_blackboard_hypothesis"`) {
		t.Fatalf("expected downgrade_to_blackboard_hypothesis, got: %s", resultText(rStatic))
	}

	// 2. Identical baseline_hash == probe_hash -> quarantined deception.
	rDecoy, err := gateTool.Call(context.Background(), json.RawMessage(`{
		"task_id": "200",
		"target": "http://10.10.1.5/api/user",
		"title": "Suspected IDOR",
		"proof_basis": "executed-live",
		"measured_impact": "1 of 1 returned 200",
		"evidence_ref": "traffic#22",
		"baseline_hash": "aabbccdd",
		"probe_hash": "aabbccdd"
	}`), nil)
	if err != nil || rDecoy.IsError || !strings.Contains(resultText(rDecoy), `"quarantine_deception"`) {
		t.Fatalf("expected quarantine_deception, got: %s", resultText(rDecoy))
	}

	// 3. Valid executed-live proof with different baseline/probe hashes -> approve_for_report.
	rOK, err := gateTool.Call(context.Background(), json.RawMessage(`{
		"task_id": "200",
		"target": "http://10.10.1.5/api/orders/999",
		"title": "Horizontal IDOR on orders API",
		"proof_basis": "executed-live",
		"measured_impact": "3 of 3 cross-tenant order IDs returned full PII",
		"evidence_ref": "traffic#301,traffic#302",
		"baseline_hash": "11112222",
		"probe_hash": "33334444"
	}`), nil)
	if err != nil || rOK.IsError || !strings.Contains(resultText(rOK), `"approve_for_report"`) {
		t.Fatalf("expected approve_for_report, got: %s", resultText(rOK))
	}
}

func TestBootstrapTargetSurfaceFastPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Server", "nginx/1.24")
			_, _ = w.Write([]byte(`<html><title>RuoYi-Vue Management</title><script>fetch("/api/v1/system/config")</script></html>`))
		case "/v3/api-docs":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"openapi":"3.0.0","paths":{"/api/v1/users":{"get":{"parameters":[{"name":"userId","in":"query"}]}}}}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	rules, err := guard.ParseFenceRules([]string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	g := guard.New()
	g.SetFence(true, rules)
	task := &Task{ID: "201", FenceEnabled: true, Guard: g}
	s := &Server{m: &Manager{tasks: map[string]*Task{"201": task}}}
	bootTool := s.toolBootstrapTargetSurface()

	// Out-of-fence blocked.
	rBlk, err := bootTool.Call(context.Background(), json.RawMessage(`{"task_id":"201","base_url":"http://192.168.55.55:8080"}`), nil)
	if err != nil || !rBlk.IsError || !strings.Contains(resultText(rBlk), "electronic fence blocked") {
		t.Fatalf("expected fence block, got err=%v res=%+v", err, rBlk)
	}

	// In-fence bootstrap extracts endpoints, matches RuoYi OSS candidate, and matches Redis baseline PoC.
	payload, _ := json.Marshal(map[string]any{
		"task_id":  "201",
		"base_url": srv.URL,
		"ports":    []int{6379},
		"techs":    []string{"RuoYi"},
	})
	rOK, err := bootTool.Call(context.Background(), payload, nil)
	if err != nil || rOK.IsError {
		t.Fatalf("bootstrap_target_surface failed: err=%v res=%+v", err, rOK)
	}
	txt := resultText(rOK)
	for _, want := range []string{"/api/v1/users", "/api/v1/system/config", `"component":"ruoyi"`, "infra-redis-unauth-probe", `"L1_BASELINE"`} {
		if !strings.Contains(txt, want) {
			t.Fatalf("expected %q in bootstrap output: %s", want, txt)
		}
	}
}
