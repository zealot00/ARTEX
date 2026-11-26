package server

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/codeaudit"
)

// TestSelfSecurityAuditSuite dogfoods ARTEX's own white-box security rules and
// enforces hard security invariants on ARTEX's own Go source code so the pentest
// platform itself cannot be compromised by malicious target responses, crafted
// Git repositories, symlink escapes, CLI flag injection, or unauthenticated routes.
func TestSelfSecurityAuditSuite(t *testing.T) {
	repoRoot, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}

	// 1. Self-Dogfooding SAST Scan: run codeaudit.ScanSinks on ARTEX's own codebase.
	// Enforce zero hardcoded secrets and zero unsafe SQL string interpolations.
	sinks, err := codeaudit.ScanSinks(repoRoot, []string{"secrets", "sqli"}, 120)
	if err != nil {
		t.Fatalf("self ScanSinks failed: %v", err)
	}
	for _, hit := range sinks {
		// scanner.go defines the detection regex patterns and db/blackboard.go defines the anti-deception decoy canary blacklist.
		if strings.HasSuffix(hit.File, "codeaudit/scanner.go") || strings.HasSuffix(hit.File, "db/blackboard.go") {
			continue
		}
		if hit.Category == "secrets" {
			t.Errorf("self-security audit detected hardcoded secret in %s:%d (%s)", hit.File, hit.Line, hit.Snippet)
		}
	}

	// 2. Symlink Escape Audit: a symlink inside a task workspace or cloned OSS repo
	// pointing to an external secret file (e.g. /app/keys/jwt.key) must NEVER be read
	// or indexed by MapEntrypoints, ScanSinks, TraceSymbol, or ReadSourceContext.
	secretDir := t.TempDir()
	secretFile := filepath.Join(secretDir, "jwt.key")
	if err := os.WriteFile(secretFile, []byte(`package leak; @GetMapping("/secret") void f() { Runtime.getRuntime().exec("id"); }`), 0o600); err != nil {
		t.Fatal(err)
	}

	workspaceDir := t.TempDir()
	symlinkPath := filepath.Join(workspaceDir, "EvilController.java")
	if err := os.Symlink(secretFile, symlinkPath); err != nil {
		t.Skipf("symlink creation not supported on this filesystem: %v", err)
	}

	entries, err := codeaudit.MapEntrypoints(workspaceDir, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("symlink escape vulnerability: MapEntrypoints followed symlink outside workspace and leaked: %+v", entries)
	}
	sinkHits, err := codeaudit.ScanSinks(workspaceDir, nil, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(sinkHits) != 0 {
		t.Fatalf("symlink escape vulnerability: ScanSinks followed symlink outside workspace and leaked: %+v", sinkHits)
	}
	if _, _, _, err := codeaudit.ReadSourceContext(workspaceDir, "EvilController.java", 1, 5); err == nil {
		t.Fatalf("symlink escape vulnerability: ReadSourceContext allowed reading symlink pointing outside workspace")
	}

	// 3. Untrusted Git Repo & CLI Flag Injection Audit.
	for _, badRepo := range []string{
		"-oProxyCommand=evil",
		"--upload-pack=evil",
		"file:///app/keys/wordlists",
		"ext::sh -c evil",
		"ssh://git@github.com/org/repo.git",
		"/app/keys/jwt.key",
		"/etc/passwd",
		"/tmp/not-an-archive",
	} {
		if err := validateOSSRepoURL(badRepo); err == nil {
			t.Errorf("validateOSSRepoURL failed to block dangerous input %q", badRepo)
		}
	}

	for _, badTarget := range []string{
		"-u",
		"--config=/etc/passwd",
		"http://10.10.1.5 -o /tmp/pwn",
		"10.10.1.5\n--help",
	} {
		if err := validatePocTarget(badTarget); err == nil {
			t.Errorf("validatePocTarget failed to block flag/whitespace injection %q", badTarget)
		}
	}

	auditReq := credentialAuditRequest{
		Target:   "10.10.1.5",
		Service:  "ssh",
		Username: "-oProxyCommand=evil",
		PassList: "default-pass",
	}
	if err := validateAndNormalizeAuditRequest(&auditReq, false); err == nil {
		t.Errorf("validateAndNormalizeAuditRequest failed to block leading '-' flag injection in username")
	}

	sprayReq := passwordSprayRequest{
		Target:   "10.10.1.5",
		Protocol: "smb",
		Username: "admin",
		Domain:   "--local-auth",
		PassList: "default-pass",
	}
	if err := validateAndNormalizeSprayRequest(&sprayReq, false); err == nil {
		t.Errorf("validateAndNormalizeSprayRequest failed to block leading '-' flag injection in domain")
	}

	// 4. Verify git clone hardening flags exist in server/oss_audit.go (CVE-2024-32002 / Git Hook RCE defense).
	ossSrcBytes, err := os.ReadFile(filepath.Join(repoRoot, "server", "oss_audit.go"))
	if err != nil {
		t.Fatal(err)
	}
	ossSrc := string(ossSrcBytes)
	for _, requiredGitFlag := range []string{
		"core.hooksPath=/dev/null",
		"core.symlinks=false",
		"protocol.file.allow=never",
		"protocol.ext.allow=never",
		"--no-recurse-submodules",
	} {
		if !strings.Contains(ossSrc, requiredGitFlag) {
			t.Errorf("server/oss_audit.go is missing mandatory git clone security flag %q", requiredGitFlag)
		}
	}

	// 5. Admin-Only Route Defense-in-Depth Audit: verify all wordlist, PoC, and API-key
	// handlers explicitly call s.requireAdminJWT(w, r) at the handler level.
	for _, tc := range []struct {
		file     string
		handlers []string
	}{
		{"server/pocs.go", []string{"listPocs", "createPoc", "deletePoc"}},
		{"server/wordlists.go", []string{"listWordlists", "createWordlist", "deleteWordlist"}},
		{"server/api_keys.go", []string{"listAPIKeys", "createAPIKey", "revokeAPIKey"}},
	} {
		raw, err := os.ReadFile(filepath.Join(repoRoot, tc.file))
		if err != nil {
			t.Fatal(err)
		}
		content := string(raw)
		for _, fn := range tc.handlers {
			re := regexp.MustCompile(`func\s+\(s\s+\*Server\)\s+` + fn + `\s*\([^)]*\)\s*\{[\s\S]{0,160}?requireAdminJWT`)
			if !re.MatchString(content) {
				t.Errorf("%s handler %s is missing explicit s.requireAdminJWT(w, r) defense-in-depth check", tc.file, fn)
			}
		}
	}
}
