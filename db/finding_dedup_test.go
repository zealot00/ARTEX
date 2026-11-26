package db

import "testing"

func TestShouldMergeFindingSameTypeAndProofAnchor(t *testing.T) {
	// 1. Exact real-world pair from user report: HiLink REST API + proof anchor supplement.
	hilinkExisting := existingFindingCandidate{
		ID:        1,
		VulnClass: "unauthenticated_access",
		Name:      "HiLink 路由 REST API 缺少鉴权，未认证信息泄露",
		Summary:   "192.168.3.1 (华为 HiLink 荣耀路由 Pro 2) 的 /api/device/information 未认证访问",
		AssetIDs:  []int64{101},
	}
	hilinkDup := RecordFindingInput{
		TaskID:    1,
		VulnClass: "info_disclosure",
		Name:      "HiLink REST API 未认证信息泄露 —— proof 流量绑定锚点",
		Summary:   "【proof 流量绑定锚点，不是新漏洞】 HiLink REST API 未认证响应",
		AssetIDs:  []int64{101, 202},
	}
	if ok, _ := shouldMergeFinding(hilinkExisting, hilinkDup); !ok {
		t.Fatal("expected HiLink proof anchor duplicate to merge into existing finding")
	}

	// 2. Exact real-world pair: UPnP SOAP control plane + proof anchor supplement.
	upnpExisting := existingFindingCandidate{
		ID:        2,
		VulnClass: "missing_auth",
		Name:      "192.168.3.1:37215 UPnP SOAP 控制端点未鉴权",
		Summary:   "192.168.3.1 UPnP SOAP 控制面允许未认证调用",
		AssetIDs:  []int64{101},
	}
	upnpDup := RecordFindingInput{
		TaskID:    1,
		VulnClass: "unauth",
		Name:      "UPnP SOAP 控制面未鉴权 —— proof 流量绑定",
		Summary:   "【proof 流量绑定锚点，不是新漏洞】 192.168.3.1:37215 UPnP SOAP",
		AssetIDs:  []int64{101, 203},
	}
	if ok, _ := shouldMergeFinding(upnpExisting, upnpDup); !ok {
		t.Fatal("expected UPnP SOAP duplicate to merge into existing finding")
	}

	// 3. Distinct vulnerability on the SAME asset (UPnP SOAP must NOT merge into HiLink REST API).
	if ok, _ := shouldMergeFinding(hilinkExisting, RecordFindingInput{
		TaskID:    1,
		VulnClass: "unauth",
		Name:      "192.168.3.1:37215 UPnP SOAP 控制端点未鉴权",
		Summary:   "192.168.3.1 UPnP SOAP 控制面允许未认证调用",
		AssetIDs:  []int64{101},
	}); ok {
		t.Fatal("distinct UPnP SOAP vulnerability must NOT merge into HiLink REST API finding")
	}

	// 4. Same vulnclass on DIFFERENT assets (different hosts) must NOT merge.
	if ok, _ := shouldMergeFinding(hilinkExisting, RecordFindingInput{
		TaskID:    1,
		VulnClass: "unauthenticated_access",
		Name:      "HiLink 路由 REST API 缺少鉴权",
		Summary:   "192.168.3.2 HiLink REST API",
		AssetIDs:  []int64{999},
	}); ok {
		t.Fatal("same vulnclass on a different host asset must NOT merge")
	}

	// 5. Asset-less findings with distinct summaries (matches existing finding_reasoning_test.go) must NOT merge.
	if ok, _ := shouldMergeFinding(
		existingFindingCandidate{ID: 3, VulnClass: "IDOR", Summary: "with reasoning"},
		RecordFindingInput{TaskID: 1, VulnClass: "IDOR", Summary: "without reasoning"},
	); ok {
		t.Fatal("asset-less findings with distinct summaries must NOT merge")
	}
}

func TestUnionAssetIDsAndHigherSeverity(t *testing.T) {
	u := unionAssetIDs([]int64{101, 205}, []int64{205, 102, 0})
	if len(u) != 3 || u[0] != 101 || u[1] != 102 || u[2] != 205 {
		t.Fatalf("unexpected unionAssetIDs: %v", u)
	}
	if got := higherSeverity("medium", "high"); got != "high" {
		t.Fatalf("expected high, got %q", got)
	}
	if got := higherSeverity("critical", "low"); got != "critical" {
		t.Fatalf("expected critical, got %q", got)
	}
}
