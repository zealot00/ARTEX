package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Autumn-27/artex/guard"
)

func TestAuthzReplayAndFence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("Authorization") {
		case "Bearer admin-secret":
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`{"user":"alice","balance":1000}`))
		case "Bearer low-priv":
			// Simulate broken authorization returning 200 to low-priv user.
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`{"user":"alice","balance":1000}`))
		default:
			w.WriteHeader(401)
			_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
		}
	}))
	defer srv.Close()

	rules, err := guard.ParseFenceRules([]string{srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	g := guard.New()
	g.SetFence(true, rules)
	task := &Task{ID: "77", FenceEnabled: true, Guard: g}
	s := &Server{m: &Manager{tasks: map[string]*Task{"77": task}}}

	tool := s.toolAuthzReplay()
	in, _ := json.Marshal(map[string]any{
		"task_id":          "77",
		"url":              srv.URL + "/api/orders/1",
		"method":           "GET",
		"headers":          map[string]string{"Authorization": "Bearer admin-secret"},
		"low_priv_headers": map[string]string{"Authorization": "Bearer low-priv"},
	})
	res, err := tool.Call(context.Background(), in, nil)
	if err != nil || res.IsError {
		t.Fatalf("authz_replay failed: err=%v res=%+v", err, res)
	}
	txt := resultText(res)
	if !strings.Contains(txt, `"variant":"low_priv"`) || !strings.Contains(txt, `"suspect_bypass":true`) {
		t.Fatalf("expected low_priv suspect_bypass=true, got: %s", txt)
	}

	// Out-of-fence URL must be blocked.
	blockedIn, _ := json.Marshal(map[string]any{
		"task_id": "77",
		"url":     "http://192.168.99.99/api/orders/1",
	})
	blockedRes, _ := tool.Call(context.Background(), blockedIn, nil)
	if !blockedRes.IsError || !strings.Contains(resultText(blockedRes), "electronic fence blocked") {
		t.Fatalf("expected fence block, got: %+v", blockedRes)
	}
}

func TestRaceProbeProdSafeCap(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	task := &Task{ID: "88", ProdSafeMode: true, Guard: guard.New()}
	s := &Server{m: &Manager{tasks: map[string]*Task{"88": task}}}

	tool := s.toolRaceProbe()
	in, _ := json.Marshal(map[string]any{
		"task_id":     "88",
		"url":         srv.URL + "/api/redeem",
		"concurrency": 20,
	})
	res, err := tool.Call(context.Background(), in, nil)
	if err != nil || res.IsError {
		t.Fatalf("race_probe failed: err=%v res=%+v", err, res)
	}
	txt := resultText(res)
	if !strings.Contains(txt, `"concurrency_used":5`) || hits.Load() != 5 {
		t.Fatalf("expected prod_safe cap at 5, got hits=%d txt=%s", hits.Load(), txt)
	}
}
