package server

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Autumn-27/artex/codeaudit"
	actool "github.com/Autumn-27/norma/tool"
)

var reSafeVersionTag = regexp.MustCompile(`^[A-Za-z0-9._\-+/]{1,64}$`)

// validateOSSRepoURL ensures repo_url is a valid http/https git URL or safe local archive
// and prevents flag injection (leading '-'), protocol smuggling, and sensitive host path access.
func validateOSSRepoURL(raw string) error {
	s := strings.TrimSpace(raw)
	if s == "" {
		return fmt.Errorf("repo_url or component is required")
	}
	if strings.HasPrefix(s, "-") {
		return fmt.Errorf("invalid repo_url %q: leading '-' is forbidden", raw)
	}
	if strings.ContainsAny(s, " \t\r\n") {
		return fmt.Errorf("invalid repo_url %q: whitespace is forbidden", raw)
	}
	low := strings.ToLower(s)
	if strings.HasPrefix(low, "file://") || strings.HasPrefix(low, "ext::") || strings.HasPrefix(low, "ssh://") {
		return fmt.Errorf("invalid repo_url %q: file://, ext::, and ssh:// protocols are forbidden", raw)
	}
	if strings.HasPrefix(s, "/") || strings.HasPrefix(s, "./") {
		cleaned := filepath.ToSlash(filepath.Clean(s))
		for _, forbidden := range []string{"/etc/", "/proc/", "/sys/", "/root/", "/app/keys", "/keys/", "wordlists", "jwt.key"} {
			if strings.Contains(strings.ToLower(cleaned), forbidden) {
				return fmt.Errorf("invalid repo_url %q: access to sensitive host path is forbidden", raw)
			}
		}
		if !strings.HasSuffix(low, ".zip") && !strings.HasSuffix(low, ".jar") && !strings.HasSuffix(low, ".war") {
			return fmt.Errorf("local repo_url must be a .zip, .jar, or .war archive")
		}
		return nil
	}
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" {
		return fmt.Errorf("repo_url must be an http(s) repository URL or local .zip/.jar/.war archive")
	}
	return nil
}

// extractArchiveBounded safely unpacks a .zip/.jar/.war archive into destDir with ZipSlip, symlink, and size limits.
func extractArchiveBounded(archivePath, destDir string) (int, error) {
	zr, err := zip.OpenReader(archivePath)
	if err != nil {
		return 0, err
	}
	defer zr.Close()

	destAbs, err := filepath.Abs(destDir)
	if err != nil {
		return 0, err
	}
	extracted := 0
	for _, f := range zr.File {
		if extracted >= 2000 {
			break
		}
		if f.FileInfo().Mode()&os.ModeSymlink != 0 {
			continue // never extract symlinks from untrusted archives
		}
		target := filepath.Join(destAbs, filepath.Clean(f.Name))
		rel, relErr := filepath.Rel(destAbs, target)
		if relErr != nil || strings.HasPrefix(rel, "..") {
			continue // prevent ZipSlip
		}
		if f.FileInfo().IsDir() {
			_ = os.MkdirAll(target, 0o755)
			continue
		}
		if f.UncompressedSize64 > 2*1024*1024 {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			continue
		}
		rc, openErr := f.Open()
		if openErr != nil {
			continue
		}
		outFile, createErr := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if createErr != nil {
			rc.Close()
			continue
		}
		_, _ = io.Copy(outFile, io.LimitReader(rc, 2*1024*1024))
		outFile.Close()
		rc.Close()
		extracted++
	}
	return extracted, nil
}

func (s *Server) toolOSSFetchSource() actool.CoreTool {
	return wrTool(
		"oss_fetch_source",
		"Fetches open-source component source code into the task workspace (<task_dir>/oss-src/<component>) for white-box/gray-box vulnerability auditing. Resolves well-known components (e.g. 'ruoyi', 'jeecg-boot', 'nacos', 'jumpserver', 'grafana', 'minio') or explicit Git URLs / local archives (.zip/.jar/.war) at a specific version tag, then runs an initial entrypoint and dependency summary.",
		objSchema(map[string]any{
			"task_id":   strParam("Task ID (numeric string)"),
			"component": strParam("Component/fingerprint name (e.g. 'ruoyi', 'nacos', 'jumpserver') or target folder name"),
			"repo_url":  strParam("Optional explicit Git repository URL or local archive/repo path (auto-resolved when component matches a known OSS project)"),
			"version":   strParam("Optional Git tag or branch matching the asset's detected version (e.g. 'v4.7.8')"),
		}, "task_id", "component"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var p struct {
				TaskID    string `json:"task_id"`
				Component string `json:"component"`
				RepoURL   string `json:"repo_url"`
				Version   string `json:"version"`
			}
			if err := json.Unmarshal(in, &p); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			p.Component = strings.TrimSpace(p.Component)
			p.RepoURL = strings.TrimSpace(p.RepoURL)
			p.Version = strings.TrimSpace(p.Version)

			if p.Component == "" {
				return actool.Errorf("component is required"), nil
			}
			if p.RepoURL == "" {
				if m, ok := MatchKnownOSSRepo(p.Component); ok {
					p.RepoURL = m.RepoURL
					p.Component = m.Component
				}
			}
			if err := validateOSSRepoURL(p.RepoURL); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if p.Version != "" && (strings.HasPrefix(p.Version, "-") || !reSafeVersionTag.MatchString(p.Version)) {
				return actool.Errorf(fmt.Sprintf("invalid version tag %q", p.Version)), nil
			}

			t := s.m.ResolveTask(strings.TrimSpace(p.TaskID))
			if t == nil {
				return actool.Errorf("task not found"), nil
			}
			taskRoot, err := s.resolveTaskAuditDir(p.TaskID, ".")
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}

			safeName := regexp.MustCompile(`[^a-zA-Z0-9._\-]+`).ReplaceAllString(strings.ToLower(p.Component), "-")
			safeName = strings.Trim(safeName, "-.")
			if safeName == "" {
				safeName = "oss-target"
			}
			relSubDir := filepath.ToSlash(filepath.Join("oss-src", safeName))
			destDir := filepath.Join(taskRoot, "oss-src", safeName)
			_ = os.RemoveAll(destDir)
			if err := os.MkdirAll(filepath.Dir(destDir), 0o755); err != nil {
				return actool.Errorf(err.Error()), nil
			}

			s.recordTaskOutbound(t, "oss_fetch_source", "git", p.RepoURL, "CLONE", "Fetch open-source source code for white-box audit")

			lowRepo := strings.ToLower(p.RepoURL)
			if strings.HasSuffix(lowRepo, ".zip") || strings.HasSuffix(lowRepo, ".jar") || strings.HasSuffix(lowRepo, ".war") {
				if err := os.MkdirAll(destDir, 0o755); err != nil {
					return actool.Errorf(err.Error()), nil
				}
				if _, err := extractArchiveBounded(p.RepoURL, destDir); err != nil {
					return actool.Errorf(fmt.Sprintf("extract archive failed: %v", err)), nil
				}
			} else {
				cloneCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
				defer cancel()
				args := []string{
					"-c", "core.hooksPath=/dev/null",
					"-c", "core.symlinks=false",
					"-c", "protocol.file.allow=never",
					"-c", "protocol.ext.allow=never",
					"clone", "--depth", "1", "--no-recurse-submodules",
				}
				if p.Version != "" {
					args = append(args, "--branch", p.Version)
				}
				args = append(args, "--", p.RepoURL, destDir)
				cmd := exec.CommandContext(cloneCtx, "git", args...)
				cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
				if out, err := cmd.CombinedOutput(); err != nil {
					return actool.Errorf(fmt.Sprintf("git clone failed: %v (%s)", err, strings.TrimSpace(string(out)))), nil
				}
			}

			srcCount, manifests := detectWorkspaceSourceCode(destDir)
			entrypoints, _ := codeaudit.MapEntrypoints(destDir, 30)
			advs, _, _ := codeaudit.AuditDependencies(destDir)

			return jsonResult(map[string]any{
				"component":        safeName,
				"repo_url":         p.RepoURL,
				"version":          p.Version,
				"workspace_subpath": relSubDir,
				"source_files":     srcCount,
				"manifests":        manifests,
				"entrypoint_count": len(entrypoints),
				"dep_advisories":   len(advs),
				"next_step":        fmt.Sprintf("Run code_scan_semgrep, code_scan_sinks, and code_audit_auth_gaps with path=%q, then verify findings against the live asset.", relSubDir),
			})
		},
	)
}

func (s *Server) toolCodeScanSemgrep() actool.CoreTool {
	return roTool(
		"code_scan_semgrep",
		"Semantic static code analysis tool: runs Semgrep (when available in PATH/container) alongside the built-in multi-language sink and auth-gap analyzer over a workspace directory, returning consolidated findings with file:line citations.",
		objSchema(map[string]any{
			"task_id": strParam("Task ID (numeric string)"),
			"path":    strParam("Relative directory inside the task workspace (default '.', or 'oss-src/<component>')"),
			"limit":   map[string]any{"type": "integer", "description": "Maximum findings to return (default 60, max 120)"},
		}, "task_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var p struct {
				TaskID string `json:"task_id"`
				Path   string `json:"path"`
				Limit  int    `json:"limit"`
			}
			if err := json.Unmarshal(in, &p); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if p.Limit <= 0 || p.Limit > 120 {
				p.Limit = 60
			}
			dir, err := s.resolveTaskAuditDir(p.TaskID, p.Path)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}

			engineUsed := "native-ast-and-sink-scanner"
			var semgrepFindings []map[string]any
			if semgrepBin, lookErr := exec.LookPath("semgrep"); lookErr == nil && semgrepBin != "" {
				runCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
				defer cancel()
				args := []string{"scan", "--json", "--quiet", "--metrics=off"}
				if customRules := strings.TrimSpace(os.Getenv("ARTEX_SEMGREP_RULES_DIR")); customRules != "" {
					args = append(args, "--config", customRules)
				}
				args = append(args, dir)
				cmd := exec.CommandContext(runCtx, semgrepBin, args...)
				if out, runErr := cmd.Output(); runErr == nil && len(out) > 0 {
					var parsed struct {
						Results []struct {
							CheckID string `json:"check_id"`
							Path    string `json:"path"`
							Start   struct {
								Line int `json:"line"`
							} `json:"start"`
							Extra struct {
								Message  string `json:"message"`
								Severity string `json:"severity"`
								Lines    string `json:"lines"`
							} `json:"extra"`
						} `json:"results"`
					}
					if json.Unmarshal(out, &parsed) == nil && len(parsed.Results) > 0 {
						engineUsed = "semgrep+native"
						for _, r := range parsed.Results {
							if len(semgrepFindings) >= p.Limit {
								break
							}
							relPath := r.Path
							if rel, relErr := filepath.Rel(dir, r.Path); relErr == nil {
								relPath = filepath.ToSlash(rel)
							}
							semgrepFindings = append(semgrepFindings, map[string]any{
								"rule":     r.CheckID,
								"file":     relPath,
								"line":     r.Start.Line,
								"severity": strings.ToLower(r.Extra.Severity),
								"message":  r.Extra.Message,
								"snippet":  strings.TrimSpace(r.Extra.Lines),
							})
						}
					}
				}
			}

			sinks, _ := codeaudit.ScanSinks(dir, nil, p.Limit)
			authGaps, _ := codeaudit.AuditAuthGaps(dir, p.Limit/2)
			if sinks == nil {
				sinks = []codeaudit.SinkHit{}
			}
			if authGaps == nil {
				authGaps = []codeaudit.AuthGapHit{}
			}
			if semgrepFindings == nil {
				semgrepFindings = []map[string]any{}
			}

			return jsonResult(map[string]any{
				"engine":           engineUsed,
				"semgrep_findings": semgrepFindings,
				"sink_hits":        sinks,
				"auth_gaps":        authGaps,
			})
		},
	)
}
