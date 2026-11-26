package server

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestDeploymentArtifactsAndDocsParity enforces that deployment manifests
// (docker-compose.yml, .env.example, Dockerfile, build.sh, scripts/backup.sh)
// and bilingual documentation (README.md, README_zh.md) never drift out of sync
// with runtime environment variables, mounted directories, or registered tools.
func TestDeploymentArtifactsAndDocsParity(t *testing.T) {
	repoRoot := ".."

	readRepoFile := func(rel string) string {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(repoRoot, rel))
		if err != nil {
			t.Fatalf("failed to read %s: %v", rel, err)
		}
		return string(b)
	}

	compose := readRepoFile("docker-compose.yml")
	envExample := readRepoFile(".env.example")
	dockerfile := readRepoFile("Dockerfile")
	buildSh := readRepoFile("build.sh")
	backupSh := readRepoFile("scripts/backup.sh")
	readmeEN := readRepoFile("README.md")
	readmeZH := readRepoFile("README_zh.md")

	// 1. Automatically scan Go production source files for "ARTEX_*" env var literals
	// and verify every runtime config var is wired in docker-compose.yml and .env.example.
	reEnvLiteral := regexp.MustCompile(`"(ARTEX_[A-Z0-9_]+)"`)
	// Internal markers / child-process-only env vars / experimental flags not meant for compose .env.
	internalOnlyVars := map[string]bool{
		"ARTEX_DATA":                  true,
		"ARTEX_POC_TARGET":            true,
		"ARTEX_OOB_TOKEN":             true,
		"ARTEX_OOB_URL":               true,
		"ARTEX_BTW_MAX_OUTPUT_TOKENS": true,
		"ARTEX_RSI_LESSONS":           true,
		"ARTEX_LLM_STREAM":            true,
	}
	// Container-internal vars computed directly inside docker-compose.yml (not set in .env.example).
	composeComputedVars := map[string]bool{
		"ARTEX_PG_DSN":      true,
		"ARTEX_JWT_KEY_DIR": true,
	}

	discoveredVars := map[string]string{}
	for _, dir := range []string{"agent", "server", "cmd/artex", "db"} {
		entries, err := os.ReadDir(filepath.Join(repoRoot, dir))
		if err != nil {
			t.Fatalf("readdir %s: %v", dir, err)
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			relPath := filepath.Join(dir, e.Name())
			src := readRepoFile(relPath)
			for _, m := range reEnvLiteral.FindAllStringSubmatch(src, -1) {
				v := m[1]
				if !internalOnlyVars[v] {
					discoveredVars[v] = relPath
				}
			}
		}
	}

	if len(discoveredVars) < 12 {
		t.Fatalf("expected at least 12 discovered ARTEX_* runtime env vars, got %d", len(discoveredVars))
	}
	for envVar, srcFile := range discoveredVars {
		if !strings.Contains(compose, envVar) {
			t.Errorf("runtime env var %s (defined in %s) is missing from docker-compose.yml", envVar, srcFile)
		}
		if !composeComputedVars[envVar] && !strings.Contains(envExample, envVar) {
			t.Errorf("runtime env var %s (defined in %s) is missing from .env.example", envVar, srcFile)
		}
	}

	// 2. Verify docker-compose.yml volume mounts and loopback security posture.
	for _, mustCompose := range []string{
		"image: artex:local",
		`"${ARTEX_BIND_ADDR:-127.0.0.1}:8787:8787"`,
		`"127.0.0.1:8788:8788"`,
		"./data:/app/data",
		"./keys:/app/keys",
		"./skills:/app/skills",
		"./pocs:/app/pocs",
	} {
		if !strings.Contains(compose, mustCompose) {
			t.Errorf("docker-compose.yml missing required directive %q", mustCompose)
		}
	}

	// 3. Verify Dockerfile preinstalls offline templates, PoCs, skills, and core security CLIs.
	for _, mustDocker := range []string{
		"COPY skills/ /app/skills/",
		"COPY pocs/ /app/pocs/",
		"ARTEX_POCS_DIR=/app/pocs",
		"ARTEX_NUCLEI_TEMPLATES_DIR=/opt/nuclei-templates",
		"impacket",
		"netexec",
		"bloodhound",
		"certipy-ad",
		"adidnsdump",
		"semgrep",
		"chisel",
		"kubectl",
		"/etc/pip.conf",
		"mirror.accum.se/mirror/pypi.org/simple",
		"mirrors.aliyun.com/pypi/simple",
		"pypi.tuna.tsinghua.edu.cn/simple",
	} {
		if !strings.Contains(dockerfile, mustDocker) {
			t.Errorf("Dockerfile missing required component %q", mustDocker)
		}
	}
	if strings.Contains(dockerfile, "--install-all-deps") || strings.Contains(dockerfile, "gowitness") {
		t.Errorf("Dockerfile must not use fragile 'bbot --install-all-deps' or 'gowitness' module preinstall")
	}

	// 4. Verify build.sh packages both skills/ and pocs/, and scripts/backup.sh backs up both data and keys.
	if !strings.Contains(buildSh, `cp -R skills "$package_root/"`) || !strings.Contains(buildSh, `cp -R pocs "$package_root/"`) {
		t.Errorf("build.sh must package both skills/ and pocs/ directories")
	}
	if !strings.Contains(backupSh, `TAR_TARGETS="data keys"`) {
		t.Errorf("scripts/backup.sh must include both data and keys (encrypted wordlist vault + jwt.key)")
	}

	// 5. Verify README.md and README_zh.md document all secondary-development tools and have no stale clone URLs.
	if strings.Contains(readmeEN, "github.com/BaaRai/ARTEX") || strings.Contains(readmeZH, "github.com/BaaRai/ARTEX") {
		t.Errorf("README.md or README_zh.md still contains stale github.com/BaaRai/ARTEX URL")
	}
	for _, keyFeature := range []string{
		"search_pocs",
		"run_poc",
		"run_infra_baseline",
		"oob_create_token",
		"oob_poll_hits",
		"run_credential_audit",
		"run_password_spray",
		"depth_session_open",
		"authz_replay",
		"race_probe",
		"plan_asset_hunt",
		"extract_web_contracts",
		"traffic_fuzz_audit",
		"oss_fetch_source",
		"code_scan_semgrep",
		"code_map_entrypoints",
		"code_scan_sinks",
		"code_audit_auth_gaps",
		"bb_record",
		"bb_search",
		"bb_corroborate",
		"invalidate_fact_cascade",
		"resource_lease_acquire",
		"resource_lease_release",
	} {
		if !strings.Contains(readmeEN, keyFeature) {
			t.Errorf("README.md is out of sync: missing documentation for %q", keyFeature)
		}
		if !strings.Contains(readmeZH, keyFeature) {
			t.Errorf("README_zh.md is out of sync: missing documentation for %q", keyFeature)
		}
	}
}
