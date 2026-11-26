package codeaudit

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const (
	maxFileBytes = 1024 * 1024 // 1 MiB per source file
	maxResults   = 120
)

var skipDirs = map[string]bool{
	".git":         true,
	"node_modules": true,
	"vendor":       true,
	"dist":         true,
	"build":        true,
	"target":       true,
	"out":          true,
	".next":        true,
	"__pycache__":  true,
	".venv":        true,
	"venv":         true,
	".idea":        true,
	".vscode":      true,
}

var sourceExts = map[string]bool{
	".go": true, ".java": true, ".kt": true, ".py": true,
	".js": true, ".ts": true, ".jsx": true, ".tsx": true,
	".php": true, ".rb": true, ".cs": true, ".xml": true,
	".yml": true, ".yaml": true, ".conf": true, ".properties": true,
}

// SafeResolveDir ensures targetPath stays strictly inside allowedRoot (preventing symlink/traversal escapes).
func SafeResolveDir(allowedRoot, targetPath string) (string, error) {
	rootAbs, err := filepath.Abs(strings.TrimSpace(allowedRoot))
	if err != nil {
		return "", err
	}
	rootReal, err := filepath.EvalSymlinks(rootAbs)
	if err != nil {
		rootReal = rootAbs
	}

	candidate := strings.TrimSpace(targetPath)
	if candidate == "" || candidate == "." {
		candidate = rootReal
	} else if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(rootReal, candidate)
	}
	candAbs, err := filepath.Abs(candidate)
	if err != nil {
		return "", err
	}
	candReal, err := filepath.EvalSymlinks(candAbs)
	if err != nil {
		return "", fmt.Errorf("path not accessible: %w", err)
	}
	rel, err := filepath.Rel(rootReal, candReal)
	if err != nil || strings.HasPrefix(rel, "..") {
		return "", fmt.Errorf("path %q escapes allowed workspace root", targetPath)
	}
	return candReal, nil
}

func isTestFile(name string) bool {
	low := strings.ToLower(name)
	return strings.HasSuffix(low, "_test.go") ||
		strings.HasSuffix(low, ".test.ts") ||
		strings.HasSuffix(low, ".test.js") ||
		strings.HasSuffix(low, ".spec.ts") ||
		strings.HasSuffix(low, ".spec.js") ||
		strings.HasSuffix(low, "test.java") ||
		strings.HasPrefix(low, "test_")
}

func walkSourceFiles(root string, fn func(relPath, absPath string) error) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		if d.IsDir() {
			if path != root && skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if isTestFile(d.Name()) {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(d.Name()))
		if !sourceExts[ext] {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > maxFileBytes {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return nil
		}
		return fn(filepath.ToSlash(rel), path)
	})
}

// EntrypointHit represents a discovered route, handler, or shared auth/defense hook.
type EntrypointHit struct {
	Kind      string `json:"kind"` // "route" | "shared_defense" | "auth_whitelist"
	Framework string `json:"framework"`
	File      string `json:"file"`
	Line      int    `json:"line"`
	Snippet   string `json:"snippet"`
}

type patternRule struct {
	kind      string
	framework string
	re        *regexp.Regexp
}

var entrypointRules = []patternRule{
	{kind: "route", framework: "spring", re: regexp.MustCompile(`@(?:Request|Get|Post|Put|Delete|Patch)Mapping\s*\(`)},
	{kind: "route", framework: "go-http", re: regexp.MustCompile(`(?:HandleFunc|Handle)\s*\(\s*"[^"]+"`)},
	{kind: "route", framework: "go-gin-echo", re: regexp.MustCompile(`\.(?:GET|POST|PUT|DELETE|PATCH|Any)\s*\(\s*"[^"]+"`)},
	{kind: "route", framework: "python-web", re: regexp.MustCompile(`@(?:app|router|bp)\.(?:route|get|post|put|delete|patch)\s*\(`)},
	{kind: "route", framework: "node-express", re: regexp.MustCompile(`\b(?:app|router)\.(?:get|post|put|delete|patch|all)\s*\(\s*['"][^'"]+['"]`)},
	{kind: "route", framework: "php-laravel", re: regexp.MustCompile(`Route::(?:get|post|put|delete|patch|any)\s*\(`)},
	{kind: "shared_defense", framework: "auth-middleware", re: regexp.MustCompile(`(?:HandlerInterceptor|OncePerRequestFilter|SecurityFilterChain|@PreAuthorize|requireAuth|AuthMiddleware|@login_required)`)},
	{kind: "auth_whitelist", framework: "auth-bypass-surface", re: regexp.MustCompile(`(?:permitAll\s*\(|excludePathPatterns|@Anonymous|AllowAnonymous|skipAuth|noAuth|IGNORE_URLS)`)},
}

// MapEntrypoints scans root for externally reachable routes, shared defenses, and auth whitelists.
func MapEntrypoints(root string, limit int) ([]EntrypointHit, error) {
	if limit <= 0 || limit > maxResults {
		limit = maxResults
	}
	var hits []EntrypointHit
	err := walkSourceFiles(root, func(rel, abs string) error {
		f, err := os.Open(abs)
		if err != nil {
			return nil
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), maxFileBytes)
		lineNo := 0
		for sc.Scan() {
			lineNo++
			line := sc.Text()
			for _, r := range entrypointRules {
				if r.re.MatchString(line) {
					hits = append(hits, EntrypointHit{
						Kind:      r.kind,
						Framework: r.framework,
						File:      rel,
						Line:      lineNo,
						Snippet:   clipLine(line, 180),
					})
					if len(hits) >= limit {
						return fs.SkipAll
					}
					break
				}
			}
		}
		return nil
	})
	if err == fs.SkipAll {
		err = nil
	}
	return hits, err
}

// SinkHit represents a candidate dangerous sink or business-logic flaw in source code.
type SinkHit struct {
	Category string `json:"category"`
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Snippet  string `json:"snippet"`
	Hint     string `json:"hint"`
}

type sinkRule struct {
	category string
	rule     string
	severity string
	hint     string
	re       *regexp.Regexp
}

var sinkRules = []sinkRule{
	// SQL Injection
	{category: "sqli", rule: "mybatis-dollar-interp", severity: "high", hint: "MyBatis ${} performs raw SQL interpolation; verify if attacker-controlled and replace with #{}", re: regexp.MustCompile(`\$\{[a-zA-Z0-9_.]+\}`)},
	{category: "sqli", rule: "sql-string-concat", severity: "high", hint: "Dynamic SQL query string formatting/concatenation; verify parameterization", re: regexp.MustCompile(`(?i)(?:SELECT|INSERT|UPDATE|DELETE)\b[^;\n]*(?:\+\s*[a-zA-Z_]|fmt\.Sprintf|f["']|\.format\()`)},
	{category: "sqli", rule: "jdbc-raw-statement", severity: "high", hint: "Raw JDBC Statement execution; check if input is concatenated", re: regexp.MustCompile(`\b(?:createStatement|executeQuery|executeUpdate)\s*\([^)]*\+`)},

	// Command Injection
	{category: "cmdi", rule: "java-runtime-exec", severity: "critical", hint: "OS command execution sink; trace arguments backward to HTTP/RPC entrypoints", re: regexp.MustCompile(`\b(?:Runtime\.getRuntime\(\)\.exec|new\s+ProcessBuilder)\s*\(`)},
	{category: "cmdi", rule: "python-shell-exec", severity: "critical", hint: "Python shell command execution; verify shell=True or os.system input origin", re: regexp.MustCompile(`\b(?:os\.system|os\.popen)\s*\(|subprocess\.[A-Za-z_]+\([^)]*shell\s*=\s*True`)},
	{category: "cmdi", rule: "go-sh-c-exec", severity: "critical", hint: "Shell invocation via exec.Command; verify argument origin", re: regexp.MustCompile(`exec\.Command(?:Context)?\s*\([^)]*"(?:sh|bash|cmd)"`)},
	{category: "cmdi", rule: "node-child-process", severity: "critical", hint: "Node child_process exec/execSync; check for unsanitized input", re: regexp.MustCompile(`\bchild_process\.(?:exec|execSync)\s*\(|\beval\s*\(`)},

	// Deserialization
	{category: "deser", rule: "java-deser-fastjson", severity: "critical", hint: "Java ObjectInputStream / Fastjson / Jackson polymorphic deserialization sink", re: regexp.MustCompile(`\b(?:ObjectInputStream|readObject\s*\(|JSON\.parseObject|JSON\.parse\(|enableDefaultTyping|activateDefaultTyping)\b`)},
	{category: "deser", rule: "python-pickle-yaml", severity: "critical", hint: "Unsafe Python pickle or yaml.load without SafeLoader", re: regexp.MustCompile(`\bpickle\.loads?\s*\(|\byaml\.load\s*\([^)]*\)`)},
	{category: "deser", rule: "php-unserialize", severity: "critical", hint: "PHP unserialize() sink; trace input for object injection", re: regexp.MustCompile(`\bunserialize\s*\(`)},

	// SSRF
	{category: "ssrf", rule: "outbound-http-client", severity: "high", hint: "Outbound HTTP request sink; check whether URL host/scheme is user-controlled", re: regexp.MustCompile(`\b(?:RestTemplate|HttpClients|openConnection|http\.Get|http\.NewRequest|requests\.(?:get|post|request)|urllib\.request\.urlopen)\b`)},

	// Path Traversal / ZipSlip / File Abuse
	{category: "path_file", rule: "zipslip-entry", severity: "high", hint: "Archive extraction entry; verify canonical path containment before writing (ZipSlip)", re: regexp.MustCompile(`\b(?:ZipInputStream|getNextEntry|TarArchiveEntry|extractall\s*\()`)},
	{category: "path_file", rule: "file-read-write-path", severity: "high", hint: "File path operation; check for ../ traversal or arbitrary upload path", re: regexp.MustCompile(`\b(?:Files\.readAllBytes|transferTo\s*\(|os\.ReadFile|ioutil\.ReadFile|sendFile\s*\()`)},

	// SSTI / Expression Injection
	{category: "ssti_el", rule: "expr-template-eval", severity: "critical", hint: "Expression/template evaluation sink (SpEL/OGNL/Jinja2/Velocity)", re: regexp.MustCompile(`\b(?:SpelExpressionParser|parseExpression|Ognl\.getValue|Velocity\.evaluate|render_template_string|jinja2\.Template)\b`)},

	// Auth & Business Logic Flaws (including pre-auth ticket/OTP leaks)
	{category: "auth_biz", rule: "preauth-ticket-otp-leak", severity: "high", hint: "Response/DTO returns ticket, smsCode, or OTP; verify it is not leaked before verification completes", re: regexp.MustCompile(`(?i)(?:return|put|json|map|res\.send|writeJSON)[^\n]*(?:ticket|smsCode|verifyCode|captchaCode|resetToken|otpCode)`)},
	{category: "auth_biz", rule: "tls-verify-disabled", severity: "medium", hint: "TLS certificate verification disabled (MITM risk)", re: regexp.MustCompile(`(?:InsecureSkipVerify\s*:\s*true|verify\s*=\s*False|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0)`)},
	{category: "auth_biz", rule: "jwt-weak-verify", severity: "high", hint: "JWT parsed without signature verification or alg=none", re: regexp.MustCompile(`(?i)(?:verify_signature['"]?\s*:\s*False|parseClaimsJwt\s*\(|alg["']?\s*[:=]\s*["']none)`)},

	// Hardcoded Secrets
	{category: "secrets", rule: "hardcoded-secret", severity: "high", hint: "Potential hardcoded secret/JWT key/cloud credential in source code", re: regexp.MustCompile(`(?i)(?:jwt[_-]?secret|secret[_-]?key|api[_-]?key|access[_-]?key|db[_-]?password)\s*[:=]\s*["'][A-Za-z0-9_\-!@#$%^&*+=]{8,}["']|AKIA[0-9A-Z]{16}|BEGIN (?:RSA |EC )?PRIVATE KEY`)},
}

// ScanSinks scans production source files for dangerous sinks and business-logic anti-patterns.
func ScanSinks(root string, categories []string, limit int) ([]SinkHit, error) {
	if limit <= 0 || limit > maxResults {
		limit = maxResults
	}
	catFilter := map[string]bool{}
	for _, c := range categories {
		if s := strings.ToLower(strings.TrimSpace(c)); s != "" {
			catFilter[s] = true
		}
	}

	var hits []SinkHit
	err := walkSourceFiles(root, func(rel, abs string) error {
		f, err := os.Open(abs)
		if err != nil {
			return nil
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), maxFileBytes)
		lineNo := 0
		for sc.Scan() {
			lineNo++
			line := sc.Text()
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "*") {
				continue
			}
			for _, r := range sinkRules {
				if len(catFilter) > 0 && !catFilter[r.category] {
					continue
				}
				if r.re.MatchString(line) {
					hits = append(hits, SinkHit{
						Category: r.category,
						Rule:     r.rule,
						Severity: r.severity,
						File:     rel,
						Line:     lineNo,
						Snippet:  clipLine(line, 180),
						Hint:     r.hint,
					})
					if len(hits) >= limit {
						return fs.SkipAll
					}
					break
				}
			}
		}
		return nil
	})
	if err == fs.SkipAll {
		err = nil
	}
	return hits, err
}

// SymbolRef records a definition or call-site reference to a symbol.
type SymbolRef struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	IsDef   bool   `json:"is_definition"`
	Snippet string `json:"snippet"`
}

// TraceSymbol locates definitions and call-sites for symbol across production source files.
func TraceSymbol(root, symbol string, limit int) ([]SymbolRef, error) {
	sym := strings.TrimSpace(symbol)
	if sym == "" {
		return nil, fmt.Errorf("symbol is required")
	}
	if limit <= 0 || limit > maxResults {
		limit = maxResults
	}
	wordRe, err := regexp.Compile(`\b` + regexp.QuoteMeta(sym) + `\b`)
	if err != nil {
		return nil, err
	}
	defRe := regexp.MustCompile(`(?i)\b(?:func|def|function|class|public|private|protected)\b[^(\n]*\b` + regexp.QuoteMeta(sym) + `\b`)

	var refs []SymbolRef
	err = walkSourceFiles(root, func(rel, abs string) error {
		f, err := os.Open(abs)
		if err != nil {
			return nil
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), maxFileBytes)
		lineNo := 0
		for sc.Scan() {
			lineNo++
			line := sc.Text()
			if wordRe.MatchString(line) {
				refs = append(refs, SymbolRef{
					File:    rel,
					Line:    lineNo,
					IsDef:   defRe.MatchString(line),
					Snippet: clipLine(line, 180),
				})
				if len(refs) >= limit {
					return fs.SkipAll
				}
			}
		}
		return nil
	})
	if err == fs.SkipAll {
		err = nil
	}
	sort.SliceStable(refs, func(i, j int) bool {
		if refs[i].IsDef != refs[j].IsDef {
			return refs[i].IsDef
		}
		return refs[i].File < refs[j].File
	})
	return refs, err
}

// DepAdvisory flags a high-risk dependency found in manifest files.
type DepAdvisory struct {
	Manifest string `json:"manifest"`
	Package  string `json:"package"`
	Version  string `json:"version"`
	Risk     string `json:"risk"`
}

var watchedDeps = []struct {
	needle string
	risk   string
}{
	{"fastjson", "Historic AutoType RCE family (audit version < 1.2.83 / fastjson2 migration)"},
	{"log4j-core", "Historic JNDI RCE family (audit version 2.0-2.14.1)"},
	{"shiro-core", "Historic RememberMe AES key / auth-bypass family (audit version < 1.10 & default key)"},
	{"commons-collections", "Java deserialization gadget library (audit 3.2.1 / 4.0)"},
	{"snakeyaml", "Unsafe YAML Constructor RCE (audit version < 2.0)"},
	{"xstream", "XML deserialization RCE family (audit version & allowlist config)"},
	{"jackson-databind", "Polymorphic deserialization gadgets (check enableDefaultTyping)"},
	{"struts2-core", "Historic OGNL RCE family"},
	{"spring-cloud-gateway", "Historic SpEL route injection (CVE-2022-22947)"},
	{"jsonwebtoken", "Audit JWT algorithm pinning and secret strength"},
	{"lodash", "Historic prototype pollution (audit version < 4.17.21)"},
	{"pyyaml", "Audit yaml.load() vs yaml.safe_load()"},
}

// AuditDependencies inspects go.mod, package.json, pom.xml, and requirements.txt for high-risk libraries.
func AuditDependencies(root string) ([]DepAdvisory, []string, error) {
	var manifests []string
	var advisories []DepAdvisory
	seen := map[string]bool{}

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		if d.IsDir() {
			if path != root && skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		name := strings.ToLower(d.Name())
		if name != "go.mod" && name != "package.json" && name != "pom.xml" && name != "requirements.txt" {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return nil
		}
		relSlash := filepath.ToSlash(rel)
		manifests = append(manifests, relSlash)

		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		text := string(data)
		low := strings.ToLower(text)
		for _, w := range watchedDeps {
			if !strings.Contains(low, w.needle) {
				continue
			}
			key := relSlash + "|" + w.needle
			if seen[key] {
				continue
			}
			seen[key] = true
			advisories = append(advisories, DepAdvisory{
				Manifest: relSlash,
				Package:  w.needle,
				Version:  extractVersionNear(text, w.needle),
				Risk:     w.risk,
			})
		}
		return nil
	})
	return advisories, manifests, err
}

var verRe = regexp.MustCompile(`[0-9]+\.[0-9]+(?:\.[0-9]+)?(?:-[A-Za-z0-9._]+)?`)

func extractVersionNear(text, needle string) string {
	lines := strings.Split(text, "\n")
	for i, ln := range lines {
		if strings.Contains(strings.ToLower(ln), needle) {
			window := ln
			if i+1 < len(lines) {
				window += " " + lines[i+1]
			}
			if m := verRe.FindString(window); m != "" {
				return m
			}
		}
	}
	return "unknown"
}

func clipLine(s string, max int) string {
	t := strings.TrimSpace(s)
	if len(t) <= max {
		return t
	}
	return t[:max] + "..."
}

// AuthGapHit flags a discovered route handler lacking explicit local auth annotations
// or ownership checks within its surrounding code window.
type AuthGapHit struct {
	Framework       string `json:"framework"`
	File            string `json:"file"`
	Line            int    `json:"line"`
	RouteSnippet    string `json:"route_snippet"`
	HasLocalAuth    bool   `json:"has_local_auth_guard"`
	HasOwnershipKey bool   `json:"has_ownership_check"`
	RiskNote        string `json:"risk_note"`
}

var (
	localAuthGuardRe = regexp.MustCompile(`(?i)(?:@PreAuthorize|@Secured|@RolesAllowed|@RequiresPermissions|@RequiresAuthentication|@login_required|requireAuth|requireAdminJWT|Depends\s*\([^)]*(?:auth|user|token)|checkAuth|verifyToken|currentUser)`)
	ownershipKeyRe   = regexp.MustCompile(`(?i)(?:tenant_id|tenantId|user_id|userId|owner_id|ownerId|currentUser|getUserId|Principal|Authentication)`)
	stateChangingRe  = regexp.MustCompile(`(?i)(?:Post|Put|Delete|Patch|admin|manage|export|download|delete|update|reset|transfer|approve|order|user)`)
)

// AuditAuthGaps inspects route handlers and checks a +/-10 line window around each
// route for explicit auth annotations/guards and user/tenant ownership references.
func AuditAuthGaps(root string, limit int) ([]AuthGapHit, error) {
	if limit <= 0 || limit > maxResults {
		limit = maxResults
	}
	var hits []AuthGapHit
	err := walkSourceFiles(root, func(rel, abs string) error {
		data, err := os.ReadFile(abs)
		if err != nil {
			return nil
		}
		lines := strings.Split(string(data), "\n")
		fileHasClassAuth := false
		for i := 0; i < len(lines) && i < 40; i++ {
			if localAuthGuardRe.MatchString(lines[i]) {
				fileHasClassAuth = true
				break
			}
		}
		for idx, line := range lines {
			var fw string
			for _, r := range entrypointRules {
				if r.kind == "route" && r.re.MatchString(line) {
					fw = r.framework
					break
				}
			}
			if fw == "" {
				continue
			}
			start := idx - 6
			if start < 0 {
				start = 0
			}
			end := idx + 15
			if end > len(lines) {
				end = len(lines)
			}
			window := strings.Join(lines[start:end], "\n")
			hasAuth := fileHasClassAuth || localAuthGuardRe.MatchString(window)
			hasOwner := ownershipKeyRe.MatchString(window)
			if !hasAuth || (!hasOwner && stateChangingRe.MatchString(line)) {
				note := "No local auth guard detected near route; verify global filter/whitelist coverage"
				if hasAuth && !hasOwner {
					note = "State-changing or sensitive route without explicit user/tenant ownership reference; check for IDOR/BOLA"
				}
				hits = append(hits, AuthGapHit{
					Framework:       fw,
					File:            rel,
					Line:            idx + 1,
					RouteSnippet:    clipLine(line, 180),
					HasLocalAuth:    hasAuth,
					HasOwnershipKey: hasOwner,
					RiskNote:        note,
				})
				if len(hits) >= limit {
					return fs.SkipAll
				}
			}
		}
		return nil
	})
	if err == fs.SkipAll {
		err = nil
	}
	return hits, err
}

// ReadSourceContext returns numbered lines around centerLine (+/- radius, capped at 80 lines)
// from a file strictly inside allowedRoot.
func ReadSourceContext(allowedRoot, relFile string, centerLine, radius int) (string, int, int, error) {
	full, err := SafeResolveDir(allowedRoot, relFile)
	if err != nil {
		return "", 0, 0, err
	}
	info, err := os.Stat(full)
	if err != nil || info.IsDir() {
		return "", 0, 0, fmt.Errorf("file not found: %s", relFile)
	}
	if info.Size() > maxFileBytes {
		return "", 0, 0, fmt.Errorf("file exceeds max readable size (%d bytes)", maxFileBytes)
	}
	data, err := os.ReadFile(full)
	if err != nil {
		return "", 0, 0, err
	}
	lines := strings.Split(string(data), "\n")
	if centerLine < 1 {
		centerLine = 1
	}
	if radius <= 0 {
		radius = 25
	}
	if radius > 40 {
		radius = 40
	}
	start := centerLine - radius
	if start < 1 {
		start = 1
	}
	end := centerLine + radius
	if end > len(lines) {
		end = len(lines)
	}
	var sb strings.Builder
	for i := start; i <= end; i++ {
		marker := "  "
		if i == centerLine {
			marker = ">>"
		}
		fmt.Fprintf(&sb, "%s %4d | %s\n", marker, i, lines[i-1])
	}
	return sb.String(), start, end, nil
}
