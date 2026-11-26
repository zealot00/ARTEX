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

func TestExtractIntranetSurfaceFromSamples(t *testing.T) {
	samples := []TrafficComplianceSample{
		{
			ID:     "t-intranet",
			URL:    "http://10.10.1.5:8080/config.js",
			Status: 200,
			RespHead: strings.Join([]string{
				"HTTP/1.1 200 OK",
				"X-Upstream: 10.10.2.15:8848",
			}, "\n"),
			RespBody: `const cfg = {
				ws: "ws://10.10.2.20:9001/events",
				cache: "redis://:secret@10.10.3.8:6379/0",
				k8sSvc: "auth-service.prod.svc.cluster.local:8443",
				outside: "192.168.99.99:22"
			};`,
		},
	}

	// Fence allows 10.10.0.0/16 and *.svc.cluster.local, excludes 192.168.99.99.
	allow := func(u string) bool {
		return strings.Contains(u, "10.10.") || strings.Contains(u, ".svc.cluster.local")
	}

	rep := ExtractSurfaceFromSamples("89", samples, allow)
	if len(rep.DiscoveredInternalSubnets) < 3 {
		t.Fatalf("expected >=3 /24 internal subnets (10.10.1/2/3), got %v", rep.DiscoveredInternalSubnets)
	}
	foundNode := map[string]bool{}
	for _, n := range rep.DiscoveredInternalNodes {
		foundNode[n.Host] = true
		if n.Host == "192.168.99.99" {
			t.Fatal("out-of-fence IP 192.168.99.99 should have been filtered out")
		}
	}
	for _, want := range []string{"10.10.2.15", "10.10.2.20", "10.10.3.8", "auth-service.prod.svc.cluster.local"} {
		if !foundNode[want] {
			t.Errorf("expected intranet surface node %q, got %+v", want, rep.DiscoveredInternalNodes)
		}
	}
}
