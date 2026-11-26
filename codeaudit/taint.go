package codeaudit

import (
	"bufio"
	"io/fs"
	"os"
	"regexp"
	"sort"
	"strings"
)

// TaintFlowHit represents a high-priority intra-file defect candidate where an untrusted
// external input source appears within a short line window before a dangerous sink.
type TaintFlowHit struct {
	Category       string `json:"category"`
	Rule           string `json:"rule"`
	Severity       string `json:"severity"`
	File           string `json:"file"`
	SourceLine     int    `json:"source_line"`
	SourceSnippet  string `json:"source_snippet"`
	SinkLine       int    `json:"sink_line"`
	SinkSnippet    string `json:"sink_snippet"`
	Distance       int    `json:"line_distance"`
	SanitizerSeen  bool   `json:"sanitizer_seen_in_window"`
	Confidence     string `json:"confidence"` // high | medium
	RemediationHint string `json:"remediation_hint"`
}

var (
	reUntrustedSource = regexp.MustCompile(`\b(?:r\.URL\.Query|r\.FormValue|r\.PostFormValue|r\.Header\.Get|c\.Query|c\.Param|c\.PostForm|c\.ShouldBind|req\.query|req\.body|req\.params|req\.headers|request\.args|request\.form|request\.get_json|request\.GET|request\.POST|getParameter|getHeader|getInputStream|\$_GET|\$_POST|\$_REQUEST|\$_COOKIE)\b|@(?:RequestParam|PathVariable|RequestBody|RequestHeader)\b`)
	reSanitizerCue    = regexp.MustCompile(`(?i)\b(?:filepath\.Clean|filepath\.Base|filepath\.Rel|url\.Parse|html\.EscapeString|DOMPurify|PreparedStatement|SetMaxBytes|allowlist|whitelist|validate|sanitize|disallow-doctype-decl|defusedxml|SafeLoader)\b`)
)

const taintWindowLines = 35

// TraceTaintFlows performs static intra-file source-to-sink proximity analysis to prioritize
// defect candidates where external request input flows toward a dangerous sink without an
// obvious sanitizer in the intervening window.
func TraceTaintFlows(root string, categories []string, limit int) ([]TaintFlowHit, error) {
	if limit <= 0 || limit > maxResults {
		limit = maxResults
	}
	catFilter := map[string]bool{}
	for _, c := range categories {
		if s := strings.ToLower(strings.TrimSpace(c)); s != "" {
			catFilter[s] = true
		}
	}

	var hits []TaintFlowHit
	err := walkSourceFiles(root, func(rel, abs string) error {
		f, err := os.Open(abs)
		if err != nil {
			return nil
		}
		defer f.Close()

		var lines []string
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), maxFileBytes)
		for sc.Scan() {
			lines = append(lines, sc.Text())
		}

		lastSourceLine := 0
		lastSourceText := ""
		for idx, line := range lines {
			lineNo := idx + 1
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "*") {
				continue
			}
			if reUntrustedSource.MatchString(line) {
				lastSourceLine = lineNo
				lastSourceText = clipLine(line, 140)
			}
			if lastSourceLine == 0 || lineNo-lastSourceLine > taintWindowLines {
				continue
			}
			for _, r := range sinkRules {
				if len(catFilter) > 0 && !catFilter[r.category] {
					continue
				}
				if !r.re.MatchString(line) {
					continue
				}
				// Check whether a sanitizer cue appears between source and sink.
				sanitized := false
				for w := lastSourceLine - 1; w <= idx && w < len(lines); w++ {
					if reSanitizerCue.MatchString(lines[w]) {
						sanitized = true
						break
					}
				}
				conf := "high"
				if sanitized || lineNo-lastSourceLine > 20 {
					conf = "medium"
				}
				hits = append(hits, TaintFlowHit{
					Category:        r.category,
					Rule:            r.rule,
					Severity:        r.severity,
					File:            rel,
					SourceLine:      lastSourceLine,
					SourceSnippet:   lastSourceText,
					SinkLine:        lineNo,
					SinkSnippet:     clipLine(line, 160),
					Distance:        lineNo - lastSourceLine,
					SanitizerSeen:   sanitized,
					Confidence:      conf,
					RemediationHint: r.hint,
				})
				if len(hits) >= limit {
					return fs.SkipAll
				}
				break
			}
		}
		return nil
	})
	if err == fs.SkipAll {
		err = nil
	}

	sort.Slice(hits, func(i, j int) bool {
		if hits[i].Confidence != hits[j].Confidence {
			return hits[i].Confidence == "high"
		}
		if hits[i].Distance != hits[j].Distance {
			return hits[i].Distance < hits[j].Distance
		}
		return hits[i].File < hits[j].File
	})
	return hits, err
}
