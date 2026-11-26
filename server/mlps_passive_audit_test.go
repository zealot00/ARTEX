package server

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func intPtr(v int) *int { return &v }

func TestEvaluateLateralSegmentation(t *testing.T) {
	assets := []*db.Asset{
		{
			ID:   1,
			Type: "ip",
			IP:   "10.10.1.10",
			OpenPorts: []map[string]any{
				{"port": 80, "service": "http"},
				{"port": 6379, "service": "redis"},
			},
		},
		{
			ID:   2,
			Type: "ip",
			IP:   "10.10.2.20",
			OpenPorts: []map[string]any{
				{"port": 445, "service": "smb"},
				{"port": 2375, "service": "docker"},
			},
		},
	}

	rep := EvaluateLateralSegmentation("42", assets)
	if rep.Verdict != db.CheckStatusFailed {
		t.Fatalf("expected failed verdict, got %q", rep.Verdict)
	}
	if len(rep.DistinctSubnets24) != 2 {
		t.Fatalf("expected 2 distinct /24 subnets, got %v", rep.DistinctSubnets24)
	}
	if rep.ExposedHighRisk < 3 {
		t.Fatalf("expected >=3 high-risk lateral ports (6379, 445, 2375), got %d", rep.ExposedHighRisk)
	}
	if rep.ZoneViolations < 2 {
		t.Fatalf("expected multi-subnet + web/data colocation violations, got %d", rep.ZoneViolations)
	}

	// Clean single-subnet web-only inventory should pass.
	clean := EvaluateLateralSegmentation("43", []*db.Asset{
		{ID: 3, Type: "ip", IP: "10.20.1.5", Port: intPtr(443)},
	})
	if clean.Verdict != db.CheckStatusPassed || len(clean.Risks) != 0 {
		t.Fatalf("expected clean single-web host to pass, got verdict=%q risks=%+v", clean.Verdict, clean.Risks)
	}
}

func TestInspectCapturedTrafficCompliance(t *testing.T) {
	// Unsigned JWT missing exp claim (for passive structural audit only).
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	pay := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"alice","role":"user"}`))
	jwtSample := hdr + "." + pay + "."

	findings := InspectCapturedTrafficCompliance([]TrafficComplianceSample{
		{
			ID:     "tx-1",
			URL:    "https://portal.corp.local/actuator/env",
			Status: 200,
			RespHead: strings.Join([]string{
				"HTTP/1.1 200 OK",
				"Access-Control-Allow-Origin: *",
				"Access-Control-Allow-Credentials: true",
				"Set-Cookie: JSESSIONID=abc123; Path=/",
			}, "\n"),
			RespBody: `{"ak":"LTAI5tAbCdEfGhIjKlMnOpQr","db":"jdbc:mysql://10.10.1.8:3306/app","token":"` + jwtSample + `"}`,
		},
	})

	wantCats := map[string]bool{
		"cors_wildcard_credentials":         false,
		"insecure_cookie_flags":             false,
		"missing_hsts":                      false,
		"exposed_management_or_doc_endpoint": false,
		"cloud_access_key_leak":             false,
		"connection_string_leak":            false,
		"jwt_insecure_alg":                  false,
		"jwt_missing_exp":                   false,
	}
	for _, f := range findings {
		if _, ok := wantCats[f.Category]; ok {
			wantCats[f.Category] = true
		}
		// Ensure raw AK is always masked in Snippet.
		if strings.Contains(f.Snippet, "LTAI5tAbCdEfGhIjKlMnOpQr") {
			t.Fatalf("secret was not masked in snippet: %q", f.Snippet)
		}
	}
	for cat, found := range wantCats {
		if !found {
			t.Errorf("expected passive compliance finding category %q, got %+v", cat, findings)
		}
	}
}
