package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/guard"
	"github.com/Autumn-27/artex/oob"
	actool "github.com/Autumn-27/norma/tool"
)

func resultText(r actool.Result) string {
	var sb strings.Builder
	for _, b := range r.Content {
		sb.WriteString(b.Text)
	}
	return sb.String()
}

func TestOOBCallbackAndTools(t *testing.T) {
	task := &Task{ID: "42", Guard: guard.New()}
	m := &Manager{tasks: map[string]*Task{"42": task}}
	s := &Server{
		m:      m,
		oobMgr: oob.NewTracker(),
		jwtKey: []byte("0123456789abcdef0123456789abcdef"),
	}

	createTool := s.toolOOBCreateToken()
	res, err := createTool.Call(context.Background(), json.RawMessage(`{"task_id":"42","label":"blind-ssrf"}`), nil)
	if err != nil || res.IsError {
		t.Fatalf("oob_create_token failed: err=%v res=%+v", err, res)
	}
	var created struct {
		Token        string `json:"token"`
		CallbackPath string `json:"callback_path"`
	}
	if err := json.Unmarshal([]byte(resultText(res)), &created); err != nil {
		t.Fatalf("decode create result: %v", err)
	}
	if created.Token == "" || !strings.HasPrefix(created.CallbackPath, "/oob/") {
		t.Fatalf("unexpected create output: %+v", created)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/oob/{token}", s.handleOOBCallback)
	mux.HandleFunc("/oob/{token}/{rest...}", s.handleOOBCallback)
	protected := s.requireAuth(mux)

	req := httptest.NewRequest("POST", created.CallbackPath+"/probe?from=target", strings.NewReader("whoami=www-data"))
	req.Header.Set("User-Agent", "curl/8.0")
	rec := httptest.NewRecorder()
	protected.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("expected 200 on unauthenticated OOB callback, got %d", rec.Code)
	}

	pollTool := s.toolOOBPollHits()
	pollRes, err := pollTool.Call(context.Background(), json.RawMessage(`{"task_id":"42","token":"`+created.Token+`"}`), nil)
	if err != nil || pollRes.IsError {
		t.Fatalf("oob_poll_hits failed: err=%v res=%+v", err, pollRes)
	}
	var polled struct {
		HitCount int       `json:"hit_count"`
		Hits     []oob.Hit `json:"hits"`
	}
	if err := json.Unmarshal([]byte(resultText(pollRes)), &polled); err != nil {
		t.Fatalf("decode poll result: %v", err)
	}
	if polled.HitCount != 1 || len(polled.Hits) != 1 {
		t.Fatalf("expected 1 hit, got %+v", polled)
	}
	if polled.Hits[0].Method != "POST" || polled.Hits[0].Query != "from=target" || polled.Hits[0].Body != "whoami=www-data" {
		t.Fatalf("unexpected hit payload: %+v", polled.Hits[0])
	}
}
