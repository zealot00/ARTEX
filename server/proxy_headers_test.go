package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/guard"
	"github.com/Autumn-27/artex/traffic"
	mproxy "github.com/lqqyt2423/go-mitmproxy/proxy"
	"net/url"
)

func TestTaskProxyHeaderRulesIsolationAndFence(t *testing.T) {
	tr, err := traffic.Open(t.TempDir(), "127.0.0.1:0")
	if err != nil {
		t.Fatalf("traffic.Open: %v", err)
	}
	defer tr.Close()

	rules, err := guard.ParseFenceRules([]string{"*.corp.local"})
	if err != nil {
		t.Fatal(err)
	}
	g := guard.New()
	g.SetFence(true, rules)
	task := &Task{ID: "55", FenceEnabled: true, Guard: g}
	m := &Manager{tasks: map[string]*Task{"55": task}, traffic: tr}
	s := &Server{m: m, jwtKey: []byte("0123456789abcdef0123456789abcdef")}

	// Reject wildcard, broad TLD suffixes, and host:port/path inputs to prevent credential leakage.
	for _, badHost := range []string{"*", ".", ".com", "portal.corp.local:8443", "portal.corp.local/api"} {
		reqBad := httptest.NewRequest("PUT", "/api/tasks/55/proxy-headers", strings.NewReader(`{"rules":[{"host":"`+badHost+`","headers":{"Cookie":"sid=secret"}}]}`))
		reqBad.SetPathValue("id", "55")
		recBad := httptest.NewRecorder()
		s.updateTaskProxyHeaders(recBad, reqBad)
		if recBad.Code != 400 {
			t.Fatalf("expected 400 for invalid host %q, got %d", badHost, recBad.Code)
		}
	}

	// Reject out-of-fence host.
	reqFence := httptest.NewRequest("PUT", "/api/tasks/55/proxy-headers", strings.NewReader(`{"rules":[{"host":"evil.example.com","headers":{"Cookie":"sid=secret"}}]}`))
	reqFence.SetPathValue("id", "55")
	recFence := httptest.NewRecorder()
	s.updateTaskProxyHeaders(recFence, reqFence)
	if recFence.Code != 403 {
		t.Fatalf("expected 403 for out-of-fence host, got %d", recFence.Code)
	}

	// Accept valid in-fence intranet host.
	reqOK := httptest.NewRequest("PUT", "/api/tasks/55/proxy-headers", strings.NewReader(`{"rules":[{"host":"portal.corp.local","headers":{"Authorization":"Bearer intranet-token"},"overwrite":true}]}`))
	reqOK.SetPathValue("id", "55")
	recOK := httptest.NewRecorder()
	s.updateTaskProxyHeaders(recOK, reqOK)
	if recOK.Code != 200 {
		t.Fatalf("expected 200 for valid host, got %d (%s)", recOK.Code, recOK.Body.String())
	}

	// Verify GET masks secret token.
	reqGet := httptest.NewRequest("GET", "/api/tasks/55/proxy-headers", nil)
	reqGet.SetPathValue("id", "55")
	recGet := httptest.NewRecorder()
	s.getTaskProxyHeaders(recGet, reqGet)
	if strings.Contains(recGet.Body.String(), "intranet-token") {
		t.Fatalf("expected token to be masked in GET response: %s", recGet.Body.String())
	}

	// Verify proxy Requestheaders injects only for portal.corp.local and NOT for external.com.
	uMatch, _ := url.Parse("https://portal.corp.local/api/me")
	flowMatch := &mproxy.Flow{Request: &mproxy.Request{URL: uMatch, Header: http.Header{}}}
	tr.ApplyHostHeadersForTest(flowMatch)
	if flowMatch.Request.Header.Get("Authorization") != "Bearer intranet-token" {
		t.Fatalf("expected Authorization header injected on matching host, got %q", flowMatch.Request.Header.Get("Authorization"))
	}

	uOther, _ := url.Parse("https://external.example.org/")
	flowOther := &mproxy.Flow{Request: &mproxy.Request{URL: uOther, Header: http.Header{}}}
	tr.ApplyHostHeadersForTest(flowOther)
	if flowOther.Request.Header.Get("Authorization") != "" {
		t.Fatalf("credential leaked to unmatched host: %q", flowOther.Request.Header.Get("Authorization"))
	}

	// Merge a second host rule without overwriting portal.corp.local.
	reqMerge := httptest.NewRequest("PUT", "/api/tasks/55/proxy-headers", strings.NewReader(`{"merge":true,"rules":[{"host":"api.corp.local","headers":{"Cookie":"sid=api-secret"},"overwrite":true}]}`))
	reqMerge.SetPathValue("id", "55")
	recMerge := httptest.NewRecorder()
	s.updateTaskProxyHeaders(recMerge, reqMerge)
	if recMerge.Code != 200 || !strings.Contains(recMerge.Body.String(), `"rule_count":2`) {
		t.Fatalf("expected 200 with rule_count=2 on merge, got %d (%s)", recMerge.Code, recMerge.Body.String())
	}
	flowPortal := &mproxy.Flow{Request: &mproxy.Request{URL: uMatch, Header: http.Header{}}}
	tr.ApplyHostHeadersForTest(flowPortal)
	if flowPortal.Request.Header.Get("Authorization") != "Bearer intranet-token" {
		t.Fatalf("merge overwrote prior host rule: %q", flowPortal.Request.Header.Get("Authorization"))
	}
	uAPI, _ := url.Parse("https://api.corp.local/v1/users")
	flowAPI := &mproxy.Flow{Request: &mproxy.Request{URL: uAPI, Header: http.Header{}}}
	tr.ApplyHostHeadersForTest(flowAPI)
	if flowAPI.Request.Header.Get("Cookie") != "sid=api-secret" {
		t.Fatalf("merged host rule not applied: %q", flowAPI.Request.Header.Get("Cookie"))
	}
}
