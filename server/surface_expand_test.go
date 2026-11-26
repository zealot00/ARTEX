package server

import (
	"strings"
	"testing"
)

func TestExtractSurfaceFromSamples(t *testing.T) {
	samples := []TrafficComplianceSample{
		{
			ID:     "t1",
			URL:    "https://portal.corp.local/login",
			Status: 200,
			RespHead: strings.Join([]string{
				"HTTP/1.1 200 OK",
				"Location: /dashboard?tab=overview",
				"Content-Security-Policy: connect-src 'self' https://api.corp.local https://cdn.evil-outside.example",
			}, "\n"),
			RespBody: `<html><body>
				<form action="/api/v1/auth/login" method="post">
					<input name="username" />
					<input name="password" type="password" />
				</form>
				<script>
					axios.post('/api/v1/orders/export');
					const q = "query GetTenantUsers { users { id } }";
				</script>
			</body></html>`,
		},
		{
			ID:       "t2",
			URL:      "https://portal.corp.local/robots.txt",
			Status:   200,
			RespHead: "HTTP/1.1 200 OK",
			RespBody: "User-agent: *\nDisallow: /internal/admin-panel\n",
		},
	}

	// Enforce electronic fence: only *.corp.local is in scope.
	allow := func(u string) bool {
		return strings.Contains(u, ".corp.local")
	}

	rep := ExtractSurfaceFromSamples("88", samples, allow)
	if rep.FenceFilteredOut == 0 {
		t.Fatal("expected out-of-fence host cdn.evil-outside.example to be filtered out")
	}

	wantURLs := map[string]bool{
		"https://portal.corp.local/dashboard":            false,
		"https://portal.corp.local/api/v1/auth/login":    false,
		"https://portal.corp.local/api/v1/orders/export": false,
		"https://portal.corp.local/internal/admin-panel": false,
		"https://portal.corp.local/graphql":              false,
	}
	for _, ep := range rep.DiscoveredEndpoints {
		if _, ok := wantURLs[ep.URL]; ok {
			wantURLs[ep.URL] = true
		}
	}
	for u, found := range wantURLs {
		if !found {
			t.Errorf("expected expanded surface endpoint %q, got %+v", u, rep.DiscoveredEndpoints)
		}
	}

	foundAPIHost := false
	for _, h := range rep.DiscoveredHosts {
		if h == "api.corp.local" {
			foundAPIHost = true
		}
		if strings.Contains(h, "evil-outside") {
			t.Fatalf("out-of-fence host leaked into discovered_hosts: %q", h)
		}
	}
	if !foundAPIHost {
		t.Fatalf("expected CSP sibling host api.corp.local in %v", rep.DiscoveredHosts)
	}
}
