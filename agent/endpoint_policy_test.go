package agent

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Autumn-27/norma/llm"
)

func TestEndpointPolicyAllowlistAndRequireBaseURL(t *testing.T) {
	t.Setenv(envLLMHostAllowlist, "127.0.0.1:11434,llm.internal,.corp.local,10.20.0.0/16")
	t.Setenv(envLLMRequireBaseURL, "")

	for _, okURL := range []string{
		"http://127.0.0.1:11434/v1",
		"https://llm.internal/v1",
		"https://llm.internal:8443/anthropic",
		"https://gw.corp.local/v1",
		"http://10.20.1.5:8080/v1",
	} {
		if err := ValidateEndpoint(llm.FormatOpenAI, okURL); err != nil {
			t.Errorf("expected allowlisted %q to pass, got: %v", okURL, err)
		}
	}

	for _, badURL := range []string{
		"",
		"https://api.openai.com/v1",
		"https://api.anthropic.com",
		"http://127.0.0.1:9999/v1", // port-pinned rule 127.0.0.1:11434 must not match other ports
		"http://10.21.0.1/v1",
		"https://evilcorp.local/v1",
		"ftp://llm.internal/v1",
	} {
		if err := ValidateEndpoint(llm.FormatOpenAI, badURL); err == nil {
			t.Errorf("expected %q to be rejected by allowlist", badURL)
		}
	}

	// Config.NewProvider must enforce the policy before calling Norma's NewProvider.
	if _, err := ConfigFrom("anthropic", "m", "", "sk-ant", "").NewProvider(); err == nil {
		t.Fatal("expected empty BaseURL to fail when allowlist is active")
	}
	if _, err := ConfigFrom("openai", "m", "https://api.openai.com/v1", "sk-oai", "").NewProvider(); err == nil {
		t.Fatal("expected public OpenAI BaseURL to fail when allowlist is active")
	}
}

func TestLLMClientBlocksHTTP30xRedirects(t *testing.T) {
	var evilHits atomic.Int32
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		evilHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(evil.Close)

	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+"/v1/messages", http.StatusTemporaryRedirect)
	}))
	t.Cleanup(gw.Close)

	prov, err := ConfigFrom("anthropic", "m", gw.URL, "secret-key", "").NewProvider()
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	_, _, _, callErr := prov.Complete(t.Context(), llm.CompletionRequest{
		Messages: []llm.Message{{Role: llm.RoleUser, Content: []llm.ContentBlock{{Type: llm.BlockText, Text: "hi"}}}},
	})
	if callErr == nil || !strings.Contains(callErr.Error(), "redirects are disabled") {
		t.Fatalf("expected redirect block error, got: %v", callErr)
	}
	if evilHits.Load() != 0 {
		t.Fatalf("redirected request reached third-party target %d times", evilHits.Load())
	}
}

func TestValidateProxyURL(t *testing.T) {
	if u, err := ValidateProxyURL("  "); err != nil || u != nil {
		t.Fatalf("empty proxy: u=%v err=%v", u, err)
	}
	if _, err := ValidateProxyURL("127.0.0.1:8080"); err == nil {
		t.Fatal("expected missing scheme to error")
	}
	if _, err := ValidateProxyURL("ftp://127.0.0.1:8080"); err == nil {
		t.Fatal("expected unsupported scheme to error")
	}
	if u, err := ValidateProxyURL("socks5://127.0.0.1:1080"); err != nil || u == nil {
		t.Fatalf("valid socks5 proxy failed: u=%v err=%v", u, err)
	}
}
