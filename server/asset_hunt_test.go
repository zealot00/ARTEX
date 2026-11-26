package server

import (
	"archive/zip"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/guard"
	"github.com/Autumn-27/artex/traffic"
	"net/url"
)

func TestAssetHuntMatrixAndOSSMatching(t *testing.T) {
	port6379 := 6379
	assets := []*db.Asset{
		{
			ID:           10,
			Type:         "http_service",
			URL:          "http://10.10.1.20:8080",
			Technologies: []string{"RuoYi-Vue 3.8.7", "Spring Boot"},
		},
		{
			ID:     11,
			Type:   "endpoint",
			URL:    "http://10.10.1.20:8080/api/v1/user/profile",
			Method: "GET",
			Params: []map[string]any{
				{"name": "userId", "location": "query"},
				{"name": "callbackUrl", "location": "query"},
			},
		},
		{
			ID:          12,
			Type:        "other_service",
			IP:          "10.10.1.21",
			Port:        &port6379,
			ServiceName: "redis",
		},
	}

	covered := map[int64]bool{12: true}
	matrix := BuildAssetHuntMatrix(77, assets, covered, 20)
	if matrix.TotalAssets != 3 || matrix.CoveredAssets != 1 || matrix.UncoveredAssets != 2 {
		t.Fatalf("unexpected matrix counts: %+v", matrix)
	}
	if len(matrix.Recommendations) != 3 {
		t.Fatalf("expected 3 recommendations, got %d", len(matrix.Recommendations))
	}
	// Uncovered assets must be prioritized ahead of covered asset #12.
	if matrix.Recommendations[2].AssetID != 12 || !matrix.Recommendations[2].Covered {
		t.Fatalf("expected covered asset #12 last, got %+v", matrix.Recommendations)
	}
	var foundOSS, foundIDOR bool
	for _, rec := range matrix.Recommendations {
		if rec.AssetID == 10 && rec.OSSCandidate != nil && rec.OSSCandidate.Component == "ruoyi" {
			foundOSS = true
		}
		if rec.AssetID == 11 {
			for _, tg := range rec.Tags {
				if tg == "idor_bola" {
					foundIDOR = true
				}
			}
		}
	}
	if !foundOSS {
		t.Fatalf("expected RuoYi OSS candidate on asset #10, got %+v", matrix.Recommendations)
	}
	if !foundIDOR {
		t.Fatalf("expected idor_bola tag on endpoint asset #11, got %+v", matrix.Recommendations)
	}
}

func TestExtractWebContractsOpenAPIAndJS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v3/api-docs":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"openapi": "3.0.0",
				"paths": {
					"/api/v1/orders": {
						"get": {
							"parameters": [{"name": "orderId", "in": "query"}]
						}
					}
				}
			}`))
		case "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><head><script src="/static/app.js"></script></head></html>`))
		case "/static/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = w.Write([]byte(`const a = "/api/v1/admin/export?fileId=100"; const b = "/internal/metrics";`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	rules, err := guard.ParseFenceRules([]string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	g := guard.New()
	g.SetFence(true, rules)
	task := &Task{ID: "88", FenceEnabled: true, Guard: g}
	s := &Server{m: &Manager{tasks: map[string]*Task{"88": task}}}
	tool := s.toolExtractWebContracts()

	// Out-of-fence target must be blocked.
	resBlocked, err := tool.Call(context.Background(), json.RawMessage(`{"task_id":"88","base_url":"http://192.168.99.99:8080"}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !resBlocked.IsError || !strings.Contains(resultText(resBlocked), "electronic fence blocked") {
		t.Fatalf("expected fence block, got %+v", resBlocked)
	}

	// In-fence target extracts both OpenAPI and JS bundle routes.
	inPayload, _ := json.Marshal(map[string]any{
		"task_id":         "88",
		"base_url":        srv.URL,
		"register_assets": false,
	})
	resOK, err := tool.Call(context.Background(), inPayload, nil)
	if err != nil || resOK.IsError {
		t.Fatalf("extract_web_contracts failed: err=%v res=%+v", err, resOK)
	}
	txt := resultText(resOK)
	for _, want := range []string{"/api/v1/orders", "/api/v1/admin/export", "/internal/metrics", "idor_bola"} {
		if !strings.Contains(txt, want) {
			t.Fatalf("expected %q in extract_web_contracts output: %s", want, txt)
		}
	}
}

func TestOSSFetchSourceArchiveAndSemgrepScan(t *testing.T) {
	tmp := t.TempDir()
	archivePath := filepath.Join(tmp, "demo-oss.zip")
	zf, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(zf)
	w, err := zw.Create("src/main/java/com/example/AdminController.java")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte(`package com.example;
import org.springframework.web.bind.annotation.*;
@RestController
public class AdminController {
    @GetMapping("/api/admin/users")
    public String listUsers(String filter) {
        return query("SELECT * FROM users WHERE name = '" + filter + "'");
    }
}
`))
	_ = zw.Close()
	_ = zf.Close()

	task := &Task{ID: "91"}
	s := &Server{m: &Manager{dir: tmp, tasks: map[string]*Task{"91": task}}}

	fetchTool := s.toolOSSFetchSource()
	// Flag-injection repo_url must be rejected.
	resBad, err := fetchTool.Call(context.Background(), json.RawMessage(`{"task_id":"91","component":"demo","repo_url":"--upload-pack=evil"}`), nil)
	if err != nil || !resBad.IsError {
		t.Fatalf("expected flag injection repo_url to fail, got err=%v res=%+v", err, resBad)
	}

	fetchPayload, _ := json.Marshal(map[string]any{
		"task_id":   "91",
		"component": "demo-oss",
		"repo_url":  archivePath,
	})
	resFetch, err := fetchTool.Call(context.Background(), fetchPayload, nil)
	if err != nil || resFetch.IsError {
		t.Fatalf("oss_fetch_source failed: err=%v res=%+v", err, resFetch)
	}
	if !strings.Contains(resultText(resFetch), `"oss-src/demo-oss"`) || !strings.Contains(resultText(resFetch), `"entrypoint_count":1`) {
		t.Fatalf("unexpected oss_fetch_source output: %s", resultText(resFetch))
	}

	scanTool := s.toolCodeScanSemgrep()
	scanPayload, _ := json.Marshal(map[string]any{
		"task_id": "91",
		"path":    "oss-src/demo-oss",
	})
	resScan, err := scanTool.Call(context.Background(), scanPayload, nil)
	if err != nil || resScan.IsError {
		t.Fatalf("code_scan_semgrep failed: err=%v res=%+v", err, resScan)
	}
	scanTxt := resultText(resScan)
	if !strings.Contains(scanTxt, "sql-string-concat") || !strings.Contains(scanTxt, "/api/admin/users") {
		t.Fatalf("expected sink and auth-gap hits in code_scan_semgrep output: %s", scanTxt)
	}
}

func TestTrafficFuzzAuditBatchAuthVerification(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulates a broken auth check that returns 200 even when Authorization header is stripped.
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"status":"ok","billing_rows":3}`))
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	tr, err := traffic.Open(t.TempDir(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()

	targetURL := srv.URL + "/api/v1/admin/billing?userId=1"
	if _, err := tr.DB().Exec(`INSERT INTO exchanges(id,ts,host,method,url_template,url,status,content_type,req_len,resp_len,path)
VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		"ex-1", 1000, u.Host, "GET", "/api/v1/admin/billing", targetURL, 200, "application/json", 0, 32, "p"); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.DB().Exec(`INSERT INTO exchange_bodies(id,req_head,req_body,resp_head,resp_body)
VALUES(?,?,?,?,?)`,
		"ex-1", "GET /api/v1/admin/billing?userId=1 HTTP/1.1\nHost: "+u.Host+"\nAuthorization: Bearer secret-jwt\n", []byte(""), "HTTP/1.1 200 OK\n", []byte(`{"status":"ok"}`)); err != nil {
		t.Fatal(err)
	}

	task := &Task{ID: "92", Guard: guard.New()}
	s := &Server{m: &Manager{tasks: map[string]*Task{"92": task}, traffic: tr}}
	tool := s.toolTrafficFuzzAudit()

	payload, _ := json.Marshal(map[string]any{
		"task_id": "92",
		"host":    u.Host,
	})
	res, err := tool.Call(context.Background(), payload, nil)
	if err != nil || res.IsError {
		t.Fatalf("traffic_fuzz_audit failed: err=%v res=%+v", err, res)
	}
	txt := resultText(res)
	if !strings.Contains(txt, `"suspect_auth_bypass":true`) || !strings.Contains(txt, `"suspect_count":1`) {
		t.Fatalf("expected suspect_auth_bypass=true in traffic_fuzz_audit output: %s", txt)
	}
}

func TestUncertaintyBlackboardAntiDeceptionAndAutoReactivation(t *testing.T) {
	tr, err := traffic.Open(t.TempDir(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()

	task := &Task{ID: "95", Guard: guard.New()}
	s := &Server{m: &Manager{tasks: map[string]*Task{"95": task}, traffic: tr}}

	recTool := s.toolBBRecord()
	searchTool := s.toolBBSearch()
	corrTool := s.toolBBCorroborate()

	// 1. Worker A posts a deferred 403 endpoint waiting for auth_session and a precondition_need waiting for internal_path.
	resDef, err := recTool.Call(context.Background(), json.RawMessage(`{
		"task_id": "95",
		"kind": "deferred_endpoint",
		"target": "http://10.10.1.5:8080/api/v1/finance/export",
		"topic": "Finance export API returned 403 without session token",
		"precondition_tag": "auth_session",
		"author": "intent#1"
	}`), nil)
	if err != nil || resDef.IsError {
		t.Fatalf("bb_record deferred_endpoint failed: err=%v res=%+v", err, resDef)
	}

	resNeed, err := recTool.Call(context.Background(), json.RawMessage(`{
		"task_id": "95",
		"kind": "precondition_need",
		"target": "http://10.10.1.5:8080/api/v1/download",
		"topic": "File read primitive confirmed, need deployment root path",
		"precondition_tag": "internal_path",
		"author": "intent#2"
	}`), nil)
	if err != nil || resNeed.IsError {
		t.Fatalf("bb_record precondition_need failed: err=%v res=%+v", err, resNeed)
	}

	// 2. Anti-Deception Gate: posting a Gingerbread/AWS canary token or identical baseline/probe hash must auto-quarantine.
	resCanary, err := recTool.Call(context.Background(), json.RawMessage(`{
		"task_id": "95",
		"kind": "anomaly",
		"target": "http://10.10.1.5:8080/.env",
		"topic": "Found AWS key AKIAIOSFODNN7EXAMPLE in response",
		"author": "intent#3"
	}`), nil)
	if err != nil || resCanary.IsError {
		t.Fatalf("bb_record canary failed: err=%v res=%+v", err, resCanary)
	}
	if !strings.Contains(resultText(resCanary), `"quarantined":true`) || !strings.Contains(resultText(resCanary), `"epistemic_state":"quarantined"`) {
		t.Fatalf("expected canary entry to be auto-quarantined, got: %s", resultText(resCanary))
	}

	resSameHash, err := recTool.Call(context.Background(), json.RawMessage(`{
		"task_id": "95",
		"kind": "hypothesis",
		"target": "http://10.10.1.5:8080/api/debug",
		"topic": "Suspected debug bypass",
		"baseline_hash": "deadbeef01",
		"probe_hash": "deadbeef01",
		"author": "intent#3"
	}`), nil)
	if err != nil || resSameHash.IsError || !strings.Contains(resultText(resSameHash), `"quarantined":true`) {
		t.Fatalf("expected identical baseline/probe hash to be quarantined, got: %s", resultText(resSameHash))
	}

	// 3. Worker B discovers the internal path and posts a corroborated anomaly with precondition_tag="internal_path".
	resPath, err := recTool.Call(context.Background(), json.RawMessage(`{
		"task_id": "95",
		"kind": "anomaly",
		"target": "http://10.10.1.5:8080/actuator/env",
		"topic": "Actuator leaked app root /opt/corp/finance-service",
		"precondition_tag": "internal_path",
		"author": "intent#4"
	}`), nil)
	if err != nil || resPath.IsError {
		t.Fatalf("bb_record anomaly failed: err=%v res=%+v", err, resPath)
	}
	var posted struct {
		Entry db.BlackboardEntry `json:"entry"`
	}
	_ = json.Unmarshal([]byte(resultText(resPath)), &posted)

	resCorr, err := corrTool.Call(context.Background(), json.RawMessage(`{
		"entry_id": `+jsonNumber(posted.Entry.ID)+`,
		"epistemic_state": "corroborated",
		"note": "Verified path in stack trace",
		"author": "intent#5"
	}`), nil)
	if err != nil || resCorr.IsError || !strings.Contains(resultText(resCorr), `"epistemic_state":"corroborated"`) {
		t.Fatalf("bb_corroborate failed: err=%v res=%+v", err, resCorr)
	}

	// Configure proxy auth headers for task 95 (satisfies auth_session precondition).
	tr.SetTaskHostHeaderRules("95", []traffic.HostHeaderRule{
		{TaskID: "95", Host: "10.10.1.5", Headers: map[string]string{"Authorization": "Bearer live-jwt"}, Overwrite: true},
	})

	// 4. Verify bb_search and Planner runtime context surface UNBLOCKED surfaces and QUARANTINED warnings.
	resSearch, err := searchTool.Call(context.Background(), json.RawMessage(`{"task_id":"95"}`), nil)
	if err != nil || resSearch.IsError || !strings.Contains(resultText(resSearch), "Finance export API") {
		t.Fatalf("bb_search failed: err=%v res=%+v", err, resSearch)
	}

	ctxText := s.buildPlannerRuntimeContext(95, t.TempDir())
	for _, mustContain := range []string{
		"[UNBLOCKED & READY TO RE-TEST]",
		"Finance export API returned 403 without session token",
		"File read primitive confirmed, need deployment root path",
		"[QUARANTINED DECEPTION / CANARY WARNING]",
	} {
		if !strings.Contains(ctxText, mustContain) {
			t.Fatalf("expected PlannerRuntimeContext to contain %q, got:\n%s", mustContain, ctxText)
		}
	}
}

func TestConcurrentResourceLeaseCoordinatorAndFreshnessGate(t *testing.T) {
	task := &Task{ID: "96"}
	s := &Server{m: &Manager{tasks: map[string]*Task{"96": task}}}

	acqTool := s.toolResourceLeaseAcquire()
	relTool := s.toolResourceLeaseRelease()

	// Worker 1 acquires exclusive_mutate lease on cred:admin.
	r1, err := acqTool.Call(context.Background(), json.RawMessage(`{
		"task_id": "96",
		"resource_key": "cred:admin",
		"mode": "exclusive_mutate",
		"holder": "intent#10",
		"purpose": "password reset workflow test"
	}`), nil)
	if err != nil || r1.IsError || !strings.Contains(resultText(r1), `"acquired":true`) {
		t.Fatalf("expected lease acquisition to succeed, got: %s", resultText(r1))
	}

	// Worker 2 attempting to acquire cred:admin concurrently must be blocked with conflict_reason.
	r2, err := acqTool.Call(context.Background(), json.RawMessage(`{
		"task_id": "96",
		"resource_key": "cred:admin",
		"mode": "shared_read",
		"holder": "intent#11",
		"purpose": "authenticated API crawl"
	}`), nil)
	if err != nil || r2.IsError || !strings.Contains(resultText(r2), `"acquired":false`) {
		t.Fatalf("expected concurrent conflicting lease to be rejected, got: %s", resultText(r2))
	}

	// Planner runtime context must show active lease.
	ctxText := s.buildPlannerRuntimeContext(96, t.TempDir())
	if !strings.Contains(ctxText, "cred:admin[exclusive_mutate by intent#10]") {
		t.Fatalf("expected active lease in planner context, got:\n%s", ctxText)
	}

	// Release by intent#10 unblocks intent#11.
	_, _ = relTool.Call(context.Background(), json.RawMessage(`{"task_id":"96","resource_key":"cred:admin","holder":"intent#10"}`), nil)
	r3, err := acqTool.Call(context.Background(), json.RawMessage(`{
		"task_id": "96",
		"resource_key": "cred:admin",
		"mode": "shared_read",
		"holder": "intent#11",
		"purpose": "authenticated API crawl"
	}`), nil)
	if err != nil || r3.IsError || !strings.Contains(resultText(r3), `"acquired":true`) {
		t.Fatalf("expected lease acquisition after release to succeed, got: %s", resultText(r3))
	}

	// Verify Inherited Asset Freshness Gate in BuildAssetHuntMatrix.
	inheritedAsset := &db.Asset{
		ID:         501,
		Type:       "http_service",
		URL:        "http://10.10.9.9:8080",
		TaskSource: "inherited",
		TaskIDs:    []int64{1, 96},
	}
	matrix := BuildAssetHuntMatrix(96, []*db.Asset{inheritedAsset}, nil, 10)
	if len(matrix.Recommendations) != 1 || !strings.Contains(matrix.Recommendations[0].Rationale, "INHERITED/HISTORICAL ASSET") {
		t.Fatalf("expected inherited freshness gate warning on asset #501, got: %+v", matrix.Recommendations)
	}
}

func jsonNumber(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}


