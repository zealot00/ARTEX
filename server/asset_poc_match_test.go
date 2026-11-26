package server

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestCorrelateAssetsWithPocs(t *testing.T) {
	// Create a tiny temp offline nuclei-templates fixture.
	tmpDir := t.TempDir()
	nacosDir := filepath.Join(tmpDir, "http", "cves")
	if err := os.MkdirAll(nacosDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nacosDir, "nacos-auth-bypass.yaml"), []byte("id: nacos-auth-bypass\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	assets := []*db.Asset{
		{
			ID:           10,
			Type:         "service",
			URL:          "http://10.10.1.5:8848/nacos",
			Technologies: []string{"Nacos/2.1.0", "Spring Boot 2.7"},
		},
		{
			ID:   11,
			Type: "ip",
			IP:   "10.10.1.6",
			Port: intPtr(6379),
		},
		{
			ID:   12,
			Type: "ip",
			IP:   "10.10.1.7",
			Port: intPtr(9999),
		},
	}

	pocs := []db.PocRecord{
		{
			ID:          1,
			Name:        "infra-redis-unauth-probe",
			Kind:        db.PocKindPythonScript,
			Severity:    "high",
			Tags:        "infra,redis,db",
			Description: "Verify Redis unauthenticated access",
		},
		{
			ID:          2,
			Name:        "nacos-default-jwt-check",
			Kind:        db.PocKindNucleiYAML,
			Severity:    "critical",
			CVE:         "CVE-2021-29441",
			Tags:        "nacos,auth",
			Description: "Check Nacos authentication configuration",
		},
	}

	// Asset 11 already has a confirmed finding; Asset 10 is pending confirmation.
	existing := []*db.DBFinding{
		{ID: 501, Status: db.FindingConfirmed, AssetIDs: []int64{11}},
	}

	rep := CorrelateAssetsWithPocs("77", assets, pocs, existing, tmpDir, 8)
	if rep.TotalAssets != 3 {
		t.Fatalf("expected 3 assets, got %d", rep.TotalAssets)
	}
	if rep.MatchedAssets != 2 {
		t.Fatalf("expected 2 matched assets (Nacos + Redis), got %d", rep.MatchedAssets)
	}
	if rep.ConfirmedAssets != 1 || rep.PendingConfirmAssets != 1 {
		t.Fatalf("expected confirmed=1 pending=1, got confirmed=%d pending=%d", rep.ConfirmedAssets, rep.PendingConfirmAssets)
	}

	byID := map[int64]AssetPocCorrelationItem{}
	for _, it := range rep.Items {
		byID[it.AssetID] = it
	}
	if byID[10].Status != "candidate" || len(byID[10].Candidates) < 2 {
		t.Fatalf("expected asset 10 (Nacos) to be candidate with private + offline PoCs, got %+v", byID[10])
	}
	if byID[11].Status != "confirmed" || len(byID[11].VerifiedFindingIDs) != 1 || byID[11].VerifiedFindingIDs[0] != 501 {
		t.Fatalf("expected asset 11 (Redis) to be confirmed with finding 501, got %+v", byID[11])
	}
	if byID[12].Status != "no_poc_match" || len(byID[12].Candidates) != 0 {
		t.Fatalf("expected asset 12 to have no_poc_match, got %+v", byID[12])
	}
}
