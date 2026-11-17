package guard

import (
	"context"
	"encoding/json"
	"testing"
)

func TestLateralGateBlocksUntilApproved(t *testing.T) {
	g := New()
	g.SetLateralGate(true, false)

	for _, cmd := range []string{
		"proxychains4 nmap -sT 10.0.1.5",
		"chisel client https://pivot.example:8000 R:socks",
		"socat TCP-LISTEN:8080,fork TCP:10.0.0.5:80",
		"ssh -N -D 1080 user@10.0.0.2",
		"impacket-psexec corp/admin@10.0.0.10",
		"bloodhound-python -d corp.local -u user -p pass",
	} {
		in, _ := json.Marshal(map[string]string{"command": cmd})
		block, msg, _ := g.Hooks().PreToolUse(context.Background(), "Bash", in)
		if !block {
			t.Errorf("expected lateral gate to block %q before approval, got allow (%s)", cmd, msg)
		}
	}

	// Normal initial recon must not be blocked by lateral gate.
	in, _ := json.Marshal(map[string]string{"command": "httpx -u https://example.com"})
	if block, msg, _ := g.Hooks().PreToolUse(context.Background(), "Bash", in); block {
		t.Fatalf("expected non-lateral recon to be allowed, got block (%s)", msg)
	}

	// Once approved, lateral commands pass.
	g.SetLateralGate(true, true)
	inLat, _ := json.Marshal(map[string]string{"command": "proxychains4 nmap -sT 10.0.1.5"})
	if block, msg, _ := g.Hooks().PreToolUse(context.Background(), "Bash", inLat); block {
		t.Fatalf("expected lateral command to be allowed after approval, got block (%s)", msg)
	}
}
