package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

type existingFindingCandidate struct {
	ID         int64
	NodeID     sql.NullInt64
	VulnClass  string
	Name       string
	Severity   string
	Summary    string
	Evidence   string
	AssetIDs   []int64
}

var (
	reNonToken      = regexp.MustCompile(`[^\p{L}\p{N}]+`)
	reIPv4Literal   = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	proofAnchorCues = []string{
		"不是新漏洞",
		"流量绑定锚点",
		"绑定锚点",
		"proof 流量",
		"proof流量",
		"not a new vulnerability",
		"traffic anchor",
		"traffic binding anchor",
		"supplemental evidence",
	}
	genericDedupStopwords = map[string]bool{
		"the": true, "and": true, "for": true, "with": true, "from": true, "that": true,
		"this": true, "http": true, "https": true, "api": true, "endpoint": true, "service": true,
		"proof": true, "traffic": true, "finding": true, "vuln": true, "vulnerability": true,
		"medium": true, "high": true, "low": true, "critical": true, "unauth": true, "auth": true,
		// Generic Chinese security/report bigrams that appear across unrelated vulns on the same host.
		"未认": true, "认证": true, "鉴权": true, "未鉴": true, "未授": true, "授权": true,
		"访问": true, "漏洞": true, "缺失": true, "缺少": true, "信息": true, "泄露": true,
		"泄漏": true, "控制": true, "端点": true, "接口": true, "服务": true, "风险": true,
		"存在": true, "允许": true, "调用": true, "响应": true, "流量": true, "绑定": true,
		"锚点": true, "不是": true, "新漏": true, "问题": true, "安全": true, "测试": true,
	}
)

func normalizeVulnClass(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	norm := b.String()
	// Canonicalize common synonymous auth/exposure class names.
	switch norm {
	case "unauth", "unauthenticated", "unauthenticatedaccess", "missingauth", "missingauthentication",
		"noauth", "brokenauthentication", "authbypass", "unauthaccess":
		return "unauthenticated_access"
	case "infodisclosure", "informationdisclosure", "sensitiveinfo", "sensitivedataexposure", "dataleak":
		return "info_disclosure"
	case "idor", "bola", "brokenobjectlevelauthorization", "horizontalprivilegeescalation":
		return "idor"
	case "sqli", "sqlinjection":
		return "sqli"
	case "xss", "crosssitescripting":
		return "xss"
	case "ssrf", "serversiderequestforgery":
		return "ssrf"
	case "rce", "remotecodeexecution", "commandinjection", "cmdi":
		return "rce"
	}
	return norm
}

func isProofAnchorNotice(name, summary string) bool {
	combined := strings.ToLower(name + " " + summary)
	for _, cue := range proofAnchorCues {
		if strings.Contains(combined, cue) {
			return true
		}
	}
	return false
}

// extractDedupTokens extracts distinctive Latin/numeric technical tokens (e.g. "hilink",
// "upnp", "soap", "37215", "actuator", "redis") plus 2-rune CJK bigrams so Chinese and
// mixed Chinese/English titles match reliably even when phrased differently.
func extractDedupTokens(texts ...string) map[string]bool {
	out := map[string]bool{}
	joined := reIPv4Literal.ReplaceAllString(strings.ToLower(strings.Join(texts, " ")), " ")
	for _, part := range reNonToken.Split(joined, -1) {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		// Split mixed Latin/digit runs vs CJK runs.
		var asciiBuf []rune
		var cjkBuf []rune
		flushASCII := func() {
			if len(asciiBuf) >= 2 {
				tok := string(asciiBuf)
				if !genericDedupStopwords[tok] {
					out[tok] = true
				}
			}
			asciiBuf = asciiBuf[:0]
		}
		flushCJK := func() {
			if len(cjkBuf) >= 2 {
				for i := 0; i+1 < len(cjkBuf); i++ {
					bg := string(cjkBuf[i : i+2])
					if !genericDedupStopwords[bg] {
						out[bg] = true
					}
				}
			}
			cjkBuf = cjkBuf[:0]
		}
		for _, r := range part {
			if unicode.Is(unicode.Han, r) {
				flushASCII()
				cjkBuf = append(cjkBuf, r)
			} else {
				flushCJK()
				asciiBuf = append(asciiBuf, r)
			}
		}
		flushASCII()
		flushCJK()
	}
	return out
}

func hasAssetOverlap(a, b []int64) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	set := make(map[int64]bool, len(a))
	for _, id := range a {
		if id > 0 {
			set[id] = true
		}
	}
	for _, id := range b {
		if id > 0 && set[id] {
			return true
		}
	}
	return false
}

func unionAssetIDs(a, b []int64) []int64 {
	set := make(map[int64]bool, len(a)+len(b))
	for _, id := range a {
		if id > 0 {
			set[id] = true
		}
	}
	for _, id := range b {
		if id > 0 {
			set[id] = true
		}
	}
	out := make([]int64, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func severityRank(sev string) int {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

func higherSeverity(a, b string) string {
	if severityRank(b) > severityRank(a) {
		return b
	}
	return a
}

// shouldMergeFinding decides whether an incoming finding in the same task is a duplicate
// or proof-anchor supplement of an existing finding on an overlapping asset.
func shouldMergeFinding(existing existingFindingCandidate, in RecordFindingInput) (bool, float64) {
	overlapAssets := hasAssetOverlap(existing.AssetIDs, in.AssetIDs)
	anchorNotice := isProofAnchorNotice(in.Name, in.Summary)

	// Require overlapping asset_ids unless the incoming report explicitly declares itself
	// a proof/traffic-binding anchor ("不是新漏洞"). This prevents collapsing unrelated
	// findings on different hosts or asset-less test fixtures.
	if !overlapAssets && !anchorNotice {
		return false, 0
	}

	exTokens := extractDedupTokens(existing.Name, existing.Summary)
	inTokens := extractDedupTokens(in.Name, in.Summary)
	shared := 0
	for tok := range inTokens {
		if exTokens[tok] {
			shared++
		}
	}
	minLen := len(exTokens)
	if len(inTokens) < minLen {
		minLen = len(inTokens)
	}
	overlapRatio := 0.0
	if minLen > 0 {
		overlapRatio = float64(shared) / float64(minLen)
	}

	exClass := normalizeVulnClass(existing.VulnClass)
	inClass := normalizeVulnClass(in.VulnClass)
	sameClass := exClass != "" && exClass == inClass

	// Case 1: Explicit proof/anchor notice ("【proof 流量绑定锚点，不是新漏洞】") with any shared topic token.
	if anchorNotice && shared >= 2 {
		return true, overlapRatio + 1.0
	}
	// Case 2: Same task + overlapping asset + same normalized vulnclass + shared topic tokens.
	if overlapAssets && sameClass && (shared >= 2 || overlapRatio >= 0.30) {
		return true, overlapRatio + 0.5
	}
	// Case 3: Same task + overlapping asset + high title/summary overlap (catches minor vulnclass wording drift
	// such as "unauthenticated_access" vs "info_disclosure" for the exact same HiLink REST API or UPnP SOAP flaw).
	if overlapAssets && shared >= 3 && overlapRatio >= 0.35 {
		return true, overlapRatio
	}
	return false, 0
}

// findDuplicateFindingTx searches active findings in the same task for a high-confidence
// duplicate that should absorb the incoming finding instead of creating a duplicate row.
func findDuplicateFindingTx(tx *sql.Tx, in RecordFindingInput) (*existingFindingCandidate, error) {
	if in.TaskID <= 0 {
		return nil, nil
	}
	rows, err := tx.Query(`
		SELECT id, node_id, vulnclass, COALESCE(name, ''), severity, summary, evidence, asset_ids
		FROM findings
		WHERE task_id = $1
		  AND COALESCE(status, 'pending') NOT IN ('duplicate', 'false_positive', 'ignored')
		ORDER BY id ASC`, in.TaskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var best *existingFindingCandidate
	bestScore := 0.0
	for rows.Next() {
		var c existingFindingCandidate
		var aidsJSON string
		if err := rows.Scan(&c.ID, &c.NodeID, &c.VulnClass, &c.Name, &c.Severity, &c.Summary, &c.Evidence, &aidsJSON); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(aidsJSON), &c.AssetIDs)
		if ok, score := shouldMergeFinding(c, in); ok && score > bestScore {
			copyC := c
			best = &copyC
			bestScore = score
		}
	}
	return best, rows.Err()
}

// mergeIntoExistingFindingTx merges supplemental evidence, assets, severity, intent edge,
// and traffic bindings into an existing finding row instead of creating a duplicate.
func mergeIntoExistingFindingTx(tx *sql.Tx, existing *existingFindingCandidate, in RecordFindingInput, prepared []PreparedTrafficEvidence) (*RecordedFinding, error) {
	mergedAssets := unionAssetIDs(existing.AssetIDs, in.AssetIDs)
	aidsJSON, _ := json.Marshal(mergedAssets)
	mergedSev := higherSeverity(existing.Severity, in.Severity)

	mergedEvidence := existing.Evidence
	newEv := strings.TrimSpace(in.Evidence)
	if newEv != "" && !strings.Contains(existing.Evidence, newEv) {
		workerLabel := strings.TrimSpace(in.Worker)
		if workerLabel == "" {
			workerLabel = "worker"
		}
		if strings.TrimSpace(mergedEvidence) != "" {
			mergedEvidence += fmt.Sprintf("\n\n--- [Merged supplemental evidence (%s)] ---\n%s", workerLabel, newEv)
		} else {
			mergedEvidence = newEv
		}
	}

	if _, err := tx.Exec(`
		UPDATE findings
		SET severity = $1,
		    evidence = $2,
		    asset_ids = $3
		WHERE id = $4`,
		mergedSev, mergedEvidence, string(aidsJSON), existing.ID,
	); err != nil {
		return nil, err
	}

	var nodeID int64
	if existing.NodeID.Valid && existing.NodeID.Int64 > 0 {
		nodeID = existing.NodeID.Int64
		for _, asset := range mergedAssets {
			if _, err := tx.Exec(`INSERT INTO exploration_anchors(node_id,asset_id) VALUES($1,$2) ON CONFLICT DO NOTHING`, nodeID, asset); err != nil {
				return nil, err
			}
		}
		if in.IntentID > 0 && in.ExplorationID > 0 {
			if _, err := tx.Exec(`INSERT INTO exploration_edges(exploration_id,src_id,rel,dst_id) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`,
				in.ExplorationID, in.IntentID, RelYields, nodeID); err != nil {
				return nil, err
			}
		}
	}

	if err := AddFindingTrafficTx(tx, existing.ID, prepared); err != nil {
		return nil, err
	}
	tr, err := FindingTrafficTx(tx, existing.ID)
	if err != nil {
		return nil, err
	}
	return &RecordedFinding{
		FindingID: existing.ID,
		NodeID:    nodeID,
		Merged:    true,
		Traffic:   tr,
	}, nil
}
