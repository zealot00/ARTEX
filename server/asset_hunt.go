package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

// OSSRepoMapping maps normalized product/technology fingerprints to well-known
// open-source repositories so white-box/gray-box source auditing can be triggered
// automatically once an asset fingerprint is confirmed.
type OSSRepoMapping struct {
	Component string `json:"component"`
	RepoURL   string `json:"repo_url"`
	Ecosystem string `json:"ecosystem"`
}

var knownOSSRepos = []struct {
	keywords  []string
	component string
	repoURL   string
	ecosystem string
}{
	{[]string{"ruoyi"}, "ruoyi", "https://github.com/yangzongzhuan/RuoYi.git", "java"},
	{[]string{"jeecg", "jeecgboot"}, "jeecg-boot", "https://github.com/jeecgboot/JeecgBoot.git", "java"},
	{[]string{"nacos"}, "nacos", "https://github.com/alibaba/nacos.git", "java"},
	{[]string{"jumpserver"}, "jumpserver", "https://github.com/jumpserver/jumpserver.git", "python"},
	{[]string{"xxl-job", "xxljob"}, "xxl-job", "https://github.com/xuxueli/xxl-job.git", "java"},
	{[]string{"grafana"}, "grafana", "https://github.com/grafana/grafana.git", "go"},
	{[]string{"harbor"}, "harbor", "https://github.com/goharbor/harbor.git", "go"},
	{[]string{"minio"}, "minio", "https://github.com/minio/minio.git", "go"},
	{[]string{"gitea"}, "gitea", "https://github.com/go-gitea/gitea.git", "go"},
	{[]string{"gitlab"}, "gitlab", "https://gitlab.com/gitlab-org/gitlab.git", "ruby"},
	{[]string{"jenkins"}, "jenkins", "https://github.com/jenkinsci/jenkins.git", "java"},
	{[]string{"keycloak"}, "keycloak", "https://github.com/keycloak/keycloak.git", "java"},
	{[]string{"superset"}, "superset", "https://github.com/apache/superset.git", "python"},
	{[]string{"metabase"}, "metabase", "https://github.com/metabase/metabase.git", "clojure"},
	{[]string{"wordpress"}, "wordpress", "https://github.com/WordPress/WordPress.git", "php"},
	{[]string{"strapi"}, "strapi", "https://github.com/strapi/strapi.git", "js"},
	{[]string{"apisix"}, "apisix", "https://github.com/apache/apisix.git", "lua"},
	{[]string{"kong"}, "kong", "https://github.com/Kong/kong.git", "lua"},
	{[]string{"argocd", "argo-cd"}, "argo-cd", "https://github.com/argoproj/argo-cd.git", "go"},
	{[]string{"halo"}, "halo", "https://github.com/halo-dev/halo.git", "java"},
	{[]string{"metersphere"}, "metersphere", "https://github.com/metersphere/metersphere.git", "java"},
	{[]string{"1panel"}, "1panel", "https://github.com/1Panel-dev/1Panel.git", "go"},
	{[]string{"alist"}, "alist", "https://github.com/alist-org/alist.git", "go"},
	{[]string{"dify"}, "dify", "https://github.com/langgenius/dify.git", "python"},
	{[]string{"ragflow"}, "ragflow", "https://github.com/infiniflow/ragflow.git", "python"},
}

// MatchKnownOSSRepo matches a technology/service fingerprint string to a known OSS repo.
func MatchKnownOSSRepo(fingerprint string) (OSSRepoMapping, bool) {
	low := strings.ToLower(strings.TrimSpace(fingerprint))
	if low == "" {
		return OSSRepoMapping{}, false
	}
	for _, item := range knownOSSRepos {
		for _, kw := range item.keywords {
			if strings.Contains(low, kw) {
				return OSSRepoMapping{
					Component: item.component,
					RepoURL:   item.repoURL,
					Ecosystem: item.ecosystem,
				}, true
			}
		}
	}
	return OSSRepoMapping{}, false
}

// HuntRecommendation describes one concrete, asset-linked assessment action.
type HuntRecommendation struct {
	AssetID       int64           `json:"asset_id"`
	AssetType     string          `json:"asset_type"`
	Target        string          `json:"target"`
	Covered       bool            `json:"covered"`
	Priority      string          `json:"priority"` // "high" | "medium" | "low"
	Tags          []string        `json:"tags"`
	Recommended   []string        `json:"recommended_tools"`
	OSSCandidate  *OSSRepoMapping `json:"oss_candidate,omitempty"`
	Rationale     string          `json:"rationale"`
}

// AssetHuntMatrix summarizes the task's attack surface and uncovered high-value assets.
type AssetHuntMatrix struct {
	TaskID          int64                `json:"task_id"`
	TotalAssets     int                  `json:"total_assets"`
	CoveredAssets   int                  `json:"covered_assets"`
	UncoveredAssets int                  `json:"uncovered_assets"`
	Recommendations []HuntRecommendation `json:"recommendations"`
}

// ClassifyEndpointParamTags assigns vulnerability-hunting categories to endpoint parameter names.
func ClassifyEndpointParamTags(params []map[string]any, rawURL string) []string {
	seen := map[string]bool{}
	var tags []string
	add := func(t string) {
		if !seen[t] {
			seen[t] = true
			tags = append(tags, t)
		}
	}
	checkName := func(name string) {
		low := strings.ToLower(strings.TrimSpace(name))
		if low == "" {
			return
		}
		switch {
		case low == "id" || strings.HasSuffix(low, "id") || strings.HasSuffix(low, "_id") ||
			strings.Contains(low, "user") || strings.Contains(low, "account") ||
			strings.Contains(low, "tenant") || strings.Contains(low, "order") ||
			strings.Contains(low, "org") || strings.Contains(low, "uid"):
			add("idor_bola")
		case strings.Contains(low, "url") || strings.Contains(low, "uri") ||
			strings.Contains(low, "callback") || strings.Contains(low, "webhook") ||
			strings.Contains(low, "redirect") || strings.Contains(low, "next") ||
			strings.Contains(low, "endpoint") || strings.Contains(low, "proxy") ||
			strings.Contains(low, "dest") || strings.Contains(low, "target"):
			add("ssrf_oob")
		case strings.Contains(low, "file") || strings.Contains(low, "path") ||
			strings.Contains(low, "dir") || strings.Contains(low, "doc") ||
			strings.Contains(low, "download") || strings.Contains(low, "upload") ||
			strings.Contains(low, "template") || strings.Contains(low, "tpl"):
			add("path_file_ssti")
		case strings.Contains(low, "amount") || strings.Contains(low, "price") ||
			strings.Contains(low, "quota") || strings.Contains(low, "coupon") ||
			strings.Contains(low, "balance") || strings.Contains(low, "count") ||
			strings.Contains(low, "status") || strings.Contains(low, "approve") ||
			strings.Contains(low, "role") || strings.Contains(low, "admin"):
			add("biz_race_massassign")
		case strings.Contains(low, "query") || strings.Contains(low, "sql") ||
			strings.Contains(low, "sort") || strings.Contains(low, "order_by") ||
			strings.Contains(low, "orderby") || strings.Contains(low, "filter") ||
			strings.Contains(low, "search") || strings.Contains(low, "keyword") ||
			strings.Contains(low, "cmd") || strings.Contains(low, "exec"):
			add("injection")
		}
	}
	for _, p := range params {
		if n, ok := p["name"].(string); ok {
			checkName(n)
		}
	}
	lowURL := strings.ToLower(rawURL)
	if strings.Contains(lowURL, "/admin") || strings.Contains(lowURL, "/manage") || strings.Contains(lowURL, "/internal") || strings.Contains(lowURL, "/actuator") {
		add("authz_admin_surface")
	}
	if strings.Contains(lowURL, "/upload") || strings.Contains(lowURL, "/import") || strings.Contains(lowURL, "/export") || strings.Contains(lowURL, "/download") {
		add("path_file_ssti")
	}
	if strings.Contains(lowURL, "/login") || strings.Contains(lowURL, "/auth") || strings.Contains(lowURL, "/token") || strings.Contains(lowURL, "/oauth") {
		add("auth_surface")
	}
	sort.Strings(tags)
	return tags
}

// BuildAssetHuntMatrix turns raw asset records and covered asset IDs into a prioritized,
// actionable vulnerability-hunting matrix.
func BuildAssetHuntMatrix(taskID int64, assets []*db.Asset, coveredIDs map[int64]bool, maxItems int) AssetHuntMatrix {
	if maxItems <= 0 {
		maxItems = 40
	}
	matrix := AssetHuntMatrix{
		TaskID:      taskID,
		TotalAssets: len(assets),
	}
	recs := make([]HuntRecommendation, 0, len(assets))
	for _, a := range assets {
		if a == nil {
			continue
		}
		covered := coveredIDs[a.ID]
		if covered {
			matrix.CoveredAssets++
		} else {
			matrix.UncoveredAssets++
		}
		rec, ok := recommendForAsset(taskID, a, covered)
		if ok {
			recs = append(recs, rec)
		}
	}
	prioRank := map[string]int{"high": 0, "medium": 1, "low": 2}
	sort.SliceStable(recs, func(i, j int) bool {
		if recs[i].Covered != recs[j].Covered {
			return !recs[i].Covered // uncovered first
		}
		if prioRank[recs[i].Priority] != prioRank[recs[j].Priority] {
			return prioRank[recs[i].Priority] < prioRank[recs[j].Priority]
		}
		return recs[i].AssetID < recs[j].AssetID
	})
	if len(recs) > maxItems {
		recs = recs[:maxItems]
	}
	matrix.Recommendations = recs
	return matrix
}

func isInheritedOrHistoricalAsset(taskID int64, a *db.Asset) bool {
	if a == nil || taskID <= 0 {
		return false
	}
	src := strings.ToLower(strings.TrimSpace(a.TaskSource))
	if src == "inherited" || src == "company_scope" || src == "historical" {
		return true
	}
	if len(a.TaskIDs) > 1 && a.TaskIDs[0] != taskID {
		return true
	}
	return false
}

func applyFreshnessGate(taskID int64, a *db.Asset, rec HuntRecommendation) HuntRecommendation {
	if isInheritedOrHistoricalAsset(taskID, a) {
		rec.Tags = dedupStrings(append(rec.Tags, "inherited_needs_reverify"))
		rec.Rationale = "[INHERITED/HISTORICAL ASSET — re-verify liveness, version, and current task scope before trusting historical properties] " + rec.Rationale
	}
	return rec
}

func recommendForAsset(taskID int64, a *db.Asset, covered bool) (HuntRecommendation, bool) {
	rec, ok := recommendForAssetCore(a, covered)
	if !ok {
		return HuntRecommendation{}, false
	}
	return applyFreshnessGate(taskID, a, rec), true
}

func recommendForAssetCore(a *db.Asset, covered bool) (HuntRecommendation, bool) {
	switch a.Type {
	case "http_service":
		target := strings.TrimSpace(a.URL)
		if target == "" {
			return HuntRecommendation{}, false
		}
		tags := []string{"web_surface"}
		tools := []string{"extract_web_contracts", "traffic_fuzz_audit"}
		var ossMatch *OSSRepoMapping
		for _, tech := range a.Technologies {
			if m, ok := MatchKnownOSSRepo(tech); ok {
				mc := m
				ossMatch = &mc
				tags = append(tags, "oss_source_audit:"+m.Component)
				tools = append(tools, "oss_fetch_source", "code_map_entrypoints", "code_scan_sinks")
				break
			}
		}
		if ossMatch == nil && a.PageTitle != "" {
			if m, ok := MatchKnownOSSRepo(a.PageTitle); ok {
				mc := m
				ossMatch = &mc
				tags = append(tags, "oss_source_audit:"+m.Component)
				tools = append(tools, "oss_fetch_source", "code_map_entrypoints", "code_scan_sinks")
			}
		}
		if len(a.Technologies) > 0 {
			tools = append(tools, "search_pocs", "run_infra_baseline")
		}
		prio := "medium"
		rationale := "Extract JS/OpenAPI contracts to discover hidden APIs and run traffic-driven authz/param audit."
		if ossMatch != nil {
			prio = "high"
			rationale = fmt.Sprintf("Detected open-source component %q: fetch source via oss_fetch_source for white-box/gray-box hunting + verify against live service.", ossMatch.Component)
		} else if len(a.Technologies) > 0 {
			prio = "high"
			rationale = fmt.Sprintf("Web service with fingerprints %v: extract JS/OpenAPI routes, match PoCs, and run traffic-driven param/authz audit.", a.Technologies)
		}
		return HuntRecommendation{
			AssetID:      a.ID,
			AssetType:    a.Type,
			Target:       target,
			Covered:      covered,
			Priority:     prio,
			Tags:         tags,
			Recommended:  dedupStrings(tools),
			OSSCandidate: ossMatch,
			Rationale:    rationale,
		}, true

	case "endpoint":
		target := strings.TrimSpace(a.URL)
		if target == "" {
			return HuntRecommendation{}, false
		}
		tags := ClassifyEndpointParamTags(a.Params, target)
		if len(tags) == 0 {
			tags = []string{"api_endpoint"}
		}
		tools := []string{"authz_replay"}
		prio := "medium"
		for _, tg := range tags {
			switch tg {
			case "idor_bola", "authz_admin_surface":
				prio = "high"
				tools = append(tools, "authz_replay", "traffic_fuzz_audit")
			case "ssrf_oob":
				prio = "high"
				tools = append(tools, "oob_create_token", "traffic_fuzz_audit")
			case "path_file_ssti", "injection":
				prio = "high"
				tools = append(tools, "traffic_fuzz_audit")
			case "biz_race_massassign":
				prio = "high"
				tools = append(tools, "race_probe", "authz_replay")
			case "auth_surface":
				tools = append(tools, "run_credential_audit", "run_password_spray")
			}
		}
		method := strings.ToUpper(strings.TrimSpace(a.Method))
		if method == "" {
			method = "GET"
		}
		return HuntRecommendation{
			AssetID:     a.ID,
			AssetType:   a.Type,
			Target:      method + " " + target,
			Covered:     covered,
			Priority:    prio,
			Tags:        tags,
			Recommended: dedupStrings(tools),
			Rationale:   fmt.Sprintf("Endpoint tagged %v based on URL/parameter semantics.", tags),
		}, true

	case "other_service", "ip":
		host := strings.TrimSpace(a.IP)
		if host == "" {
			host = strings.TrimSpace(a.Domain)
		}
		if host == "" {
			return HuntRecommendation{}, false
		}
		var ports []int
		if a.Port != nil && *a.Port > 0 {
			ports = append(ports, *a.Port)
		}
		for _, op := range a.OpenPorts {
			if pv, ok := op["port"]; ok {
				switch v := pv.(type) {
				case float64:
					if int(v) > 0 {
						ports = append(ports, int(v))
					}
				case int:
					if v > 0 {
						ports = append(ports, v)
					}
				}
			}
		}
		if len(ports) == 0 && a.ServiceName == "" {
			return HuntRecommendation{}, false
		}
		target := host
		if a.Port != nil && *a.Port > 0 {
			target = fmt.Sprintf("%s:%d", host, *a.Port)
		}
		return HuntRecommendation{
			AssetID:     a.ID,
			AssetType:   a.Type,
			Target:      target,
			Covered:     covered,
			Priority:    "high",
			Tags:        []string{"infra_service"},
			Recommended: []string{"run_infra_baseline", "run_credential_audit"},
			Rationale:   fmt.Sprintf("Infrastructure host/service (ports=%v, svc=%s): run automated port/tech baseline PoCs and credential checks.", ports, a.ServiceName),
		}, true
	}
	return HuntRecommendation{}, false
}

func dedupStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func (s *Server) computeTaskAssetHuntMatrix(taskID int64, maxItems int) (AssetHuntMatrix, error) {
	if s == nil || s.m == nil || s.m.assets == nil || taskID <= 0 {
		return AssetHuntMatrix{TaskID: taskID}, nil
	}
	assets, err := s.m.assets.QueryByTask(taskID, "", 200, 0)
	if err != nil {
		return AssetHuntMatrix{TaskID: taskID}, err
	}
	covered := map[int64]bool{}
	if intentAssets, err := s.m.assets.IntentAssets(taskID); err == nil {
		for _, ia := range intentAssets {
			covered[ia.AssetID] = true
		}
	}
	return BuildAssetHuntMatrix(taskID, assets, covered, maxItems), nil
}

func (s *Server) huntTools() []actool.CoreTool {
	return []actool.CoreTool{
		s.toolPlanAssetHunt(),
		s.toolExtractWebContracts(),
		s.toolTrafficFuzzAudit(),
		s.toolOSSFetchSource(),
		s.toolCodeScanSemgrep(),
		s.toolBBRecord(),
		s.toolBBSearch(),
		s.toolBBCorroborate(),
		s.toolInvalidateFactCascade(),
		s.toolResourceLeaseAcquire(),
		s.toolResourceLeaseRelease(),
		s.toolSolverStatus(),
		s.toolSolverPruneMechanism(),
		s.toolSolverEscalate(),
		s.toolVerifyCandidateFinding(),
		s.toolBootstrapTargetSurface(),
	}
}

func (s *Server) seedHuntTools() {
	if s.m == nil || s.m.pg == nil {
		return
	}
	agents, _ := json.Marshal([]string{"worker", "planner", "main", "auto", "pentest"})
	for _, t := range s.huntTools() {
		schema, _ := json.Marshal(t.InputSchema())
		if err := s.m.pg.SeedTool(t.Name(), t.Description(), schema, agents); err != nil {
			log.Printf("[hunt] seed tool %s: %v", t.Name(), err)
		}
	}
}

func (s *Server) toolPlanAssetHunt() actool.CoreTool {
	return roTool(
		"plan_asset_hunt",
		"Asset-driven vulnerability-hunting matrix: inspects all assets linked to the task (services, technologies, endpoints/params, open ports), compares against already-covered intent assets, and returns prioritized uncovered hunting routes (JS/OpenAPI contract extraction, traffic-driven authz/param fuzzing, infra baselines, and open-source repo candidates for white-box/gray-box auditing).",
		objSchema(map[string]any{
			"task_id":   strParam("Task ID (numeric string)"),
			"max_items": map[string]any{"type": "integer", "description": "Maximum recommendations to return (default 30, max 80)"},
		}, "task_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var p struct {
				TaskID   string `json:"task_id"`
				MaxItems int    `json:"max_items"`
			}
			if err := json.Unmarshal(in, &p); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			tid, err := strconv.ParseInt(strings.TrimSpace(p.TaskID), 10, 64)
			if err != nil || tid <= 0 {
				return actool.Errorf("invalid task_id"), nil
			}
			if p.MaxItems <= 0 {
				p.MaxItems = 30
			}
			if p.MaxItems > 80 {
				p.MaxItems = 80
			}
			matrix, err := s.computeTaskAssetHuntMatrix(tid, p.MaxItems)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(matrix)
		},
	)
}
