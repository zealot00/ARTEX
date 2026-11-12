package db

import (
	"strings"
	"testing"
)

func TestNormalizeAPIKeyScopesAndFormat(t *testing.T) {
	if IsAPIKeyFormat("eyJhbGciOiJIUzI1NiJ9.x.y") {
		t.Fatal("JWT should not match API key prefix")
	}
	if !IsAPIKeyFormat("artex_ak_0123456789abcdef") {
		t.Fatal("expected artex_ak_ prefix to match")
	}

	scopes, err := NormalizeAPIKeyScopes([]string{" tasks:read ", "tasks:create", "tasks:read", ""})
	if err != nil {
		t.Fatalf("NormalizeAPIKeyScopes: %v", err)
	}
	if len(scopes) != 2 || scopes[0] != ScopeTasksRead || scopes[1] != ScopeTasksCreate {
		t.Fatalf("unexpected scopes: %v", scopes)
	}

	if _, err := NormalizeAPIKeyScopes(nil); err == nil {
		t.Fatal("expected empty scopes to fail")
	}
	if _, err := NormalizeAPIKeyScopes([]string{"admin:all"}); err == nil {
		t.Fatal("expected unknown scope to fail")
	}

	h1 := HashAPIKey("artex_ak_abc")
	h2 := HashAPIKey("  artex_ak_abc ")
	if h1 != h2 || len(h1) != 64 || strings.Contains(h1, "artex_ak_") {
		t.Fatalf("unexpected hash: %q vs %q", h1, h2)
	}
}
