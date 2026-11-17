package guard

import (
	"regexp"
	"strings"
)

type prodSafeRule struct {
	re     *regexp.Regexp
	reason string
}

var prodSafeCommandRules = []prodSafeRule{
	{
		re:     regexp.MustCompile(`(?i)\b(?:hping3|slowloris|siege|wrk|locust)\b`),
		reason: "production-safe mode blocks DoS / load-testing tools (hping3/slowloris/siege/wrk/locust)",
	},
	{
		re:     regexp.MustCompile(`(?i)(?:^|[;&|\s])ab\s+.*-[cn]\s`),
		reason: "production-safe mode blocks ApacheBench stress testing (ab -c/-n)",
	},
	{
		re:     regexp.MustCompile(`(?i)\bsqlmap\b.*(?:--os-shell|--sql-shell|--os-pwn|--risk\s*=?\s*3)`),
		reason: "production-safe mode blocks high-risk sqlmap options (--os-shell/--sql-shell/--os-pwn/--risk=3)",
	},
	{
		re:     regexp.MustCompile(`(?i)\bffuf\b.*(?:-t|--threads)\s*=?\s*(?:[3-9]\d|\d{3,})\b`),
		reason: "production-safe mode caps ffuf concurrency to <= 20 threads",
	},
	{
		re:     regexp.MustCompile(`(?i)\bhydra\b.*(?:-t\s*=?\s*(?:[5-9]|\d{2,})\b)`),
		reason: "production-safe mode caps hydra concurrency to <= 4 tasks",
	},
	{
		re:     regexp.MustCompile(`(?i)\b(?:drop\s+(?:table|database)|truncate\s+table)\b`),
		reason: "production-safe mode blocks destructive SQL statements (DROP/TRUNCATE)",
	},
}

// CheckProdSafeCommand inspects a shell/command line for high-concurrency DoS,
// stress-testing, or destructive payloads forbidden under MLPS production-safe mode.
func CheckProdSafeCommand(cmd string) (string, bool) {
	trimmed := strings.TrimSpace(cmd)
	if trimmed == "" {
		return "", false
	}
	for _, rule := range prodSafeCommandRules {
		if rule.re.MatchString(trimmed) {
			return rule.reason, true
		}
	}
	return "", false
}
