package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestListModelsRejectsInvalidProxyAndRedirects(t *testing.T) {
	s := &Server{}

	// Malformed proxy must fail instead of falling back to a direct connection.
	var directHits atomic.Int32
	direct := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		directHits.Add(1)
		_, _ = w.Write([]byte(`{"data":[{"id":"m1"}]}`))
	}))
	t.Cleanup(direct.Close)

	resp := postJSON(t, s.pgListModels, "/api/llm/models", map[string]any{
		"provider": "openai",
		"base_url": direct.URL + "/v1",
		"api_key":  "sk-test",
		"proxy":    "://bad-proxy",
	})
	if resp["ok"] != false || directHits.Load() != 0 {
		t.Fatalf("invalid proxy was ignored or connected directly: hits=%d resp=%v", directHits.Load(), resp)
	}

	// HTTP 30x redirect from upstream must never forward API keys to a third party.
	var evilHits atomic.Int32
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		evilHits.Add(1)
		_, _ = w.Write([]byte(`{"data":[{"id":"leaked"}]}`))
	}))
	t.Cleanup(evil.Close)

	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+"/v1/models", http.StatusFound)
	}))
	t.Cleanup(redir.Close)

	resp = postJSON(t, s.pgListModels, "/api/llm/models", map[string]any{
		"provider": "anthropic",
		"base_url": redir.URL,
		"api_key":  "sk-ant-secret",
	})
	if resp["ok"] != false || evilHits.Load() != 0 {
		t.Fatalf("redirect target reached (%d hits), resp=%v", evilHits.Load(), resp)
	}
	if errMsg, _ := resp["error"].(string); !strings.Contains(errMsg, "redirects are disabled") {
		t.Fatalf("expected redirect refusal message, got %q", errMsg)
	}
}

func TestListModelsEnforcesHostAllowlist(t *testing.T) {
	t.Setenv("ARTEX_LLM_HOST_ALLOWLIST", "127.0.0.1")
	s := &Server{}

	// Empty base_url must fail before falling back to api.openai.com/api.anthropic.com.
	resp := postJSON(t, s.pgListModels, "/api/llm/models", map[string]any{
		"provider": "openai",
		"base_url": "",
		"api_key":  "sk-test",
	})
	if resp["ok"] != false {
		t.Fatalf("expected empty base_url to fail under allowlist, got %v", resp)
	}

	// Non-allowlisted host must fail without making a request.
	resp = postJSON(t, s.pgListModels, "/api/llm/models", map[string]any{
		"provider": "openai",
		"base_url": "https://api.openai.com/v1",
		"api_key":  "sk-test",
	})
	if resp["ok"] != false {
		t.Fatalf("expected public host to fail under allowlist, got %v", resp)
	}
}

func TestWebSearchDisabledByEnvPolicy(t *testing.T) {
	t.Setenv("ARTEX_DISABLE_WEB_SEARCH", "1")
	s := &Server{}
	resp := postJSON(t, s.testWebSearch, "/api/settings/web-search/test", map[string]any{
		"web_search_backend": "ddgs",
	})
	if resp["ok"] != false {
		t.Fatalf("expected testWebSearch to fail when disabled by policy, got %v", resp)
	}
}
