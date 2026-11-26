package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

// AssetPocMatchCandidate represents one PoC template/script correlated to a discovered asset.
type AssetPocMatchCandidate struct {
	Source      string `json:"source"` // private_repo | file_repo | offline_nuclei
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	Severity    string `json:"severity,omitempty"`
	CVE         string `json:"cve,omitempty"`
	Tags        string `json:"tags,omitempty"`
	Template    string `json:"template_path,omitempty"`
	Score       int    `json:"score"`
	MatchReason string `json:"match_reason"`
}

// AssetPocCorrelationItem correlates one task asset with matching PoC candidates and existing findings.
type AssetPocCorrelationItem struct {
	AssetID            int64                    `json:"asset_id"`
	AssetType          string                   `json:"asset_type"`
	Target             string                   `json:"target"`
	Fingerprints       []string                 `json:"fingerprints"`
	Status             string                   `json:"status"` // confirmed | candidate | no_poc_match
	VerifiedFindingIDs []int64                  `json:"verified_finding_ids,omitempty"`
	Candidates         []AssetPocMatchCandidate `json:"candidates"`
}

// AssetPocCorrelationReport summarizes asset-correlated PoC matching and confirmation state for a task.
type AssetPocCorrelationReport struct {
	TaskID               string                    `json:"task_id"`
	TotalAssets          int                       `json:"total_assets"`
	MatchedAssets        int                       `json:"matched_assets"`
	ConfirmedAssets      int                       `json:"confirmed_assets"`
	PendingConfirmAssets int                       `json:"pending_confirm_assets"`
	Items                []AssetPocCorrelationItem `json:"items"`
}

var portFingerprintHints = map[int][]string{
	21:    {"ftp"},
	22:    {"ssh", "openssh"},
	23:    {"telnet"},
	25:    {"smtp"},
	88:    {"kerberos"},
	139:   {"smb", "samba"},
	389:   {"ldap"},
	445:   {"smb", "samba"},
	636:   {"ldaps", "ldap"},
	1433:  {"mssql", "sqlserver"},
	1521:  {"oracle"},
	2375:  {"docker"},
	2376:  {"docker"},
	3306:  {"mysql", "mariadb"},
	3389:  {"rdp"},
	5432:  {"postgres", "postgresql"},
	5985:  {"winrm"},
	6379:  {"redis"},
	6443:  {"kubernetes", "k8s"},
	7001:  {"weblogic"},
	8080:  {"tomcat", "http"},
	8848:  {"nacos"},
	9200:  {"elasticsearch"},
	10250: {"kubelet", "k8s"},
	11211: {"memcached"},
	27017: {"mongodb"},
	37215: {"upnp", "huawei"},
}

var pocMatchStopwords = map[string]bool{
	"http": true, "https": true, "tcp": true, "udp": true, "web": true,
	"server": true, "service": true, "default": true, "unknown": true, "linux": true,
}

func normalizeFingerprintTokens(raw string) []string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" {
		return nil
	}
	var out []string
	var buf []rune
	flush := func() {
		if len(buf) >= 2 {
			tok := string(buf)
			if !pocMatchStopwords[tok] {
				out = append(out, tok)
			}
		}
		buf = buf[:0]
	}
	for _, r := range raw {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_' {
			buf = append(buf, r)
		} else {
			flush()
		}
	}
	flush()
	return out
}

func assetTargetString(a *db.Asset) string {
	if a == nil {
		return ""
	}
	if strings.TrimSpace(a.URL) != "" {
		return strings.TrimSpace(a.URL)
	}
	host := strings.TrimSpace(a.Domain)
	if host == "" {
		host = strings.TrimSpace(a.IP)
	}
	if host != "" && a.Port != nil && *a.Port > 0 {
		return fmt.Sprintf("%s:%d", host, *a.Port)
	}
	return host
}

func extractAssetFingerprints(a *db.Asset) []string {
	if a == nil {
		return nil
	}
	seen := map[string]bool{}
	add := func(tok string) {
		tok = strings.ToLower(strings.TrimSpace(tok))
		if len(tok) < 2 || pocMatchStopwords[tok] || seen[tok] {
			return
		}
		seen[tok] = true
	}
	for _, tech := range a.Technologies {
		// Split version suffix (e.g. "nginx/1.24" -> "nginx", "Spring Boot 2.7" -> "spring", "boot").
		base := strings.SplitN(tech, "/", 2)[0]
		for _, tok := range normalizeFingerprintTokens(base) {
			add(tok)
		}
	}
	for _, tok := range normalizeFingerprintTokens(a.ServiceName) {
		add(tok)
	}
	for _, tok := range normalizeFingerprintTokens(a.AppName) {
		add(tok)
	}
	if a.Port != nil && *a.Port > 0 {
		for _, hint := range portFingerprintHints[*a.Port] {
			add(hint)
		}
	}
	for _, p := range a.OpenPorts {
		var port int
		switch v := p["port"].(type) {
		case float64:
			port = int(v)
		case int:
			port = v
		}
		if port > 0 {
			for _, hint := range portFingerprintHints[port] {
				add(hint)
			}
		}
		if svc, ok := p["service"].(string); ok {
			for _, tok := range normalizeFingerprintTokens(svc) {
				add(tok)
			}
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func scorePocForFingerprints(poc db.PocRecord, fps []string) (int, []string) {
	if len(fps) == 0 {
		return 0, nil
	}
	nameLow := strings.ToLower(poc.Name)
	tagsLow := strings.ToLower(poc.Tags)
	descLow := strings.ToLower(poc.Description)
	cveLow := strings.ToLower(poc.CVE)

	tagSet := map[string]bool{}
	for _, t := range strings.Split(tagsLow, ",") {
		t = strings.TrimSpace(t)
		if t != "" {
			tagSet[t] = true
		}
	}

	score := 0
	var matched []string
	for _, fp := range fps {
		hit := false
		if tagSet[fp] {
			score += 5
			hit = true
		} else if strings.Contains(nameLow, fp) {
			score += 4
			hit = true
		} else if strings.Contains(cveLow, fp) {
			score += 4
			hit = true
		} else if strings.Contains(descLow, fp) {
			score += 2
			hit = true
		}
		if hit {
			matched = append(matched, fp)
		}
	}
	return score, matched
}

// CorrelateAssetsWithPocs matches discovered task assets against available PoC records
// and optional offline Nuclei template indexes, and cross-references existing findings
// to show confirmation status per asset.
func CorrelateAssetsWithPocs(
	taskID string,
	assets []*db.Asset,
	pocs []db.PocRecord,
	existingFindings []*db.DBFinding,
	offlineDir string,
	maxPerAsset int,
) AssetPocCorrelationReport {
	if maxPerAsset <= 0 {
		maxPerAsset = 8
	}
	if maxPerAsset > 25 {
		maxPerAsset = 25
	}

	// Build asset_id -> confirmed/active finding IDs map.
	findingsByAsset := map[int64][]int64{}
	for _, f := range existingFindings {
		if f == nil {
			continue
		}
		if f.Status == db.FindingFalsePositive || f.Status == db.FindingIgnored || f.Status == db.FindingDuplicate {
			continue
		}
		for _, aid := range f.AssetIDs {
			findingsByAsset[aid] = append(findingsByAsset[aid], f.ID)
		}
	}

	items := make([]AssetPocCorrelationItem, 0, len(assets))
	matchedAssets := 0
	confirmedAssets := 0
	pendingConfirmAssets := 0

	for _, a := range assets {
		if a == nil {
			continue
		}
		fps := extractAssetFingerprints(a)
		target := assetTargetString(a)
		if target == "" {
			continue
		}

		var cands []AssetPocMatchCandidate
		seenName := map[string]bool{}
		for _, poc := range pocs {
			score, hits := scorePocForFingerprints(poc, fps)
			if score <= 0 {
				continue
			}
			src := "private_repo"
			if poc.CreatedBy == "file" {
				src = "file_repo"
			}
			seenName[poc.Name] = true
			cands = append(cands, AssetPocMatchCandidate{
				Source:      src,
				Name:        poc.Name,
				Kind:        poc.Kind,
				Severity:    poc.Severity,
				CVE:         poc.CVE,
				Tags:        poc.Tags,
				Score:       score,
				MatchReason: "matched fingerprint: " + strings.Join(hits, ", "),
			})
		}

		// Optionally correlate against local offline nuclei-templates directory (read-only filename/tag scan).
		if strings.TrimSpace(offlineDir) != "" && len(fps) > 0 && len(cands) < maxPerAsset {
			for _, fp := range fps {
				if len(fp) < 3 {
					continue
				}
				for _, rel := range searchOfflineNucleiTemplates(offlineDir, fp, "", 3) {
					if seenName[rel] {
						continue
					}
					seenName[rel] = true
					cands = append(cands, AssetPocMatchCandidate{
						Source:      "offline_nuclei",
						Name:        rel,
						Kind:        db.PocKindNucleiYAML,
						Template:    rel,
						Score:       3,
						MatchReason: "matched offline template: " + fp,
					})
				}
			}
		}

		sort.Slice(cands, func(i, j int) bool {
			if cands[i].Score != cands[j].Score {
				return cands[i].Score > cands[j].Score
			}
			return cands[i].Name < cands[j].Name
		})
		if len(cands) > maxPerAsset {
			cands = cands[:maxPerAsset]
		}
		if cands == nil {
			cands = []AssetPocMatchCandidate{}
		}

		verifiedIDs := findingsByAsset[a.ID]
		status := "no_poc_match"
		if len(verifiedIDs) > 0 {
			status = "confirmed"
			confirmedAssets++
		} else if len(cands) > 0 {
			status = "candidate"
			pendingConfirmAssets++
		}
		if len(cands) > 0 {
			matchedAssets++
		}

		items = append(items, AssetPocCorrelationItem{
			AssetID:            a.ID,
			AssetType:          a.Type,
			Target:             target,
			Fingerprints:       fps,
			Status:             status,
			VerifiedFindingIDs: verifiedIDs,
			Candidates:         cands,
		})
	}

	// Sort matched/pending assets first for operator & planner clarity.
	sort.Slice(items, func(i, j int) bool {
		if len(items[i].Candidates) != len(items[j].Candidates) {
			return len(items[i].Candidates) > len(items[j].Candidates)
		}
		return items[i].AssetID < items[j].AssetID
	})

	return AssetPocCorrelationReport{
		TaskID:               taskID,
		TotalAssets:          len(items),
		MatchedAssets:        matchedAssets,
		ConfirmedAssets:      confirmedAssets,
		PendingConfirmAssets: pendingConfirmAssets,
		Items:                items,
	}
}

func (s *Server) buildAssetPocCorrelation(taskID string, tid int64, filterAssetID int64, maxPerAsset int) (AssetPocCorrelationReport, error) {
	var assets []*db.Asset
	if s.m != nil && s.m.assets != nil {
		var err error
		assets, err = s.m.assets.QueryByTask(tid, "", 300, 0)
		if err != nil {
			return AssetPocCorrelationReport{}, err
		}
	}
	if filterAssetID > 0 {
		filtered := assets[:0]
		for _, a := range assets {
			if a != nil && a.ID == filterAssetID {
				filtered = append(filtered, a)
			}
		}
		assets = filtered
	}

	var pocs []db.PocRecord
	seen := map[string]bool{}
	if s.m != nil && s.m.pg != nil {
		if dbPocs, err := s.m.pg.SearchPocs("", "", "", 200); err == nil {
			for _, it := range dbPocs {
				pocs = append(pocs, it)
				seen[it.Name] = true
			}
		}
	}
	for _, fp := range loadPocsFromDir(pocsDir()) {
		if seen[fp.Name] {
			continue
		}
		seen[fp.Name] = true
		pocs = append(pocs, db.PocRecord{
			Name:        fp.Name,
			Kind:        fp.Kind,
			Severity:    fp.Severity,
			CVE:         fp.CVE,
			Tags:        fp.Tags,
			Description: fp.Description,
			CreatedBy:   "file",
		})
	}

	var existingFindings []*db.DBFinding
	if s.m != nil && s.m.pg != nil {
		if rows, _, err := s.m.pg.ListFindingsPage(db.FindingFilter{TaskID: taskID}, 200, 0); err == nil {
			existingFindings = rows
		}
	}

	return CorrelateAssetsWithPocs(taskID, assets, pocs, existingFindings, nucleiTemplatesDir(), maxPerAsset), nil
}

func (s *Server) toolMatchAssetPocs() actool.CoreTool {
	return roTool(
		"match_asset_pocs",
		"Correlate discovered task assets (technologies, service names, titles, open ports) against ARTEX's private PoC repository, hot-loaded ./pocs directory, and offline nuclei-templates index, and cross-check existing findings to show which assets have matching candidate PoCs awaiting confirmation vs already confirmed.",
		objSchema(map[string]any{
			"task_id":       strParam("Task ID (numeric string)"),
			"asset_id":      map[string]any{"type": "integer", "description": "Optional single asset_id to correlate"},
			"max_per_asset": map[string]any{"type": "integer", "description": "Max candidate PoCs returned per asset (default 8, max 25)"},
		}, "task_id"),
		func(_ context.Context, raw json.RawMessage) (actool.Result, error) {
			var p struct {
				TaskID      string `json:"task_id"`
				AssetID     int64  `json:"asset_id"`
				MaxPerAsset int    `json:"max_per_asset"`
			}
			if err := json.Unmarshal(raw, &p); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			tid, err := strconv.ParseInt(strings.TrimSpace(p.TaskID), 10, 64)
			if err != nil || tid <= 0 {
				return actool.Errorf(fmt.Sprintf("invalid task_id %q", p.TaskID)), nil
			}
			rep, err := s.buildAssetPocCorrelation(p.TaskID, tid, p.AssetID, p.MaxPerAsset)
			if err != nil {
				return actool.Errorf(fmt.Sprintf("correlate asset pocs: %v", err)), nil
			}
			return jsonResult(rep)
		},
	)
}

// GET /api/tasks/{id}/asset-pocs — returns the asset-correlated PoC matching & confirmation matrix.
func (s *Server) getTaskAssetPocs(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	tid, err := strconv.ParseInt(t.ID, 10, 64)
	if err != nil || tid <= 0 {
		writeErr(w, 400, "invalid task id")
		return
	}
	var assetID int64
	if raw := strings.TrimSpace(r.URL.Query().Get("asset_id")); raw != "" {
		assetID, _ = strconv.ParseInt(raw, 10, 64)
	}
	rep, err := s.buildAssetPocCorrelation(t.ID, tid, assetID, 10)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, rep)
}
