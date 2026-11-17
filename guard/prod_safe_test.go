package guard

import (
	"context"
	"encoding/json"
	"testing"
)

func TestProdSafeGuardBlocksDoSAndHighConcurrency(t *testing.T) {
	g := New()
	g.SetProdSafe(true)

	for _, bad := range []string{
		"hping3 -S --flood 10.0.0.1",
		"wrk -t12 -c400 -d30s https://example.com/",
		"ffuf -u https://example.com/FUZZ -w words.txt -t 50",
		"hydra -L u.txt -P p.txt -t 16 ssh://10.0.0.1",
		"sqlmap -u https://example.com/?id=1 --os-shell",
		`psql -c "DROP TABLE users;"`,
	} {
		in, _ := json.Marshal(map[string]string{"command": bad})
		block, msg, _ := g.Hooks().PreToolUse(context.Background(), "Bash", in)
		if !block {
			t.Errorf("expected prodSafe to block %q, got allow (%s)", bad, msg)
		}
	}

	for _, safe := range []string{
		"sslscan --no-colour example.com:443",
		"ffuf -u https://example.com/FUZZ -w words.txt -t 10",
		"hydra -L u.txt -P p.txt -t 4 ssh://10.0.0.1",
		"sqlmap -u https://example.com/?id=1 --batch --level=2 --risk=1",
	} {
		in, _ := json.Marshal(map[string]string{"command": safe})
		block, msg, _ := g.Hooks().PreToolUse(context.Background(), "Bash", in)
		if block {
			t.Errorf("expected prodSafe to allow %q, got block (%s)", safe, msg)
		}
	}
}
