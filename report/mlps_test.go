package report

import (
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func TestMLPSMarkdownIncludesNegativeEvidenceAndFindings(t *testing.T) {
	md := MLPSMarkdown(MLPSInput{
		TaskID:            "42",
		ExternalRef:       "MLPS-2026-09",
		Title:             "核心业务系统三级等保渗透",
		Goal:              "完成等保十项基线验证与越权核查",
		ComplianceProfile: "mlps",
		ProdSafeMode:      true,
		GeneratedAt:       time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC),
		AssetCounts:       map[string]int{"service": 3, "endpoint": 12},
		Checks: []db.TaskCheck{
			{
				CheckCode: "NET-TLS",
				Domain:    "安全通信网络",
				Title:     "传输加密与 TLS 检查",
				Status:    db.CheckStatusPassed,
				Target:    "https://app.example.com",
				Evidence:  "sslscan 仅支持 TLS 1.2/1.3，无弱加密套件",
				TestedBy:  "worker",
			},
			{
				CheckCode: "AUTH-ACCESS",
				Domain:    "安全计算环境-访问控制",
				Title:     "越权访问控制验证",
				Status:    db.CheckStatusFailed,
				Target:    "/api/v1/orders/1002",
				Evidence:  "普通用户可读取他人订单详情",
				TestedBy:  "worker",
			},
		},
		Findings: []*db.Node{
			{
				Payload: []byte(`{"vulnclass":"IDOR","name":"订单水平越权","severity":"high","summary":"未校验订单归属","evidence":{"poc":"GET /api/v1/orders/1002 -> 200 OK"}}`),
			},
		},
		OutboundLogs: []db.OutboundLog{
			{
				Source:     "proxy",
				Protocol:   "https",
				TargetHost: "nvd.nist.gov",
				TargetPort: 443,
				HitCount:   3,
				Purpose:    "HTTP/HTTPS proxy egress",
				URLPreview: "https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
				FirstSeen:  time.Date(2026, 11, 17, 11, 50, 0, 0, time.UTC),
				LastSeen:   time.Date(2026, 11, 17, 11, 55, 0, 0, time.UTC),
			},
		},
	})

	for _, want := range []string{
		"等级保护渗透测试报告（MLPS 2.0）",
		"`MLPS-2026-09`",
		"通过 (已测无漏洞)",
		"未通过 (存在风险)",
		"sslscan 仅支持 TLS 1.2/1.3",
		"[HIGH] 订单水平越权",
		"任务执行期间外联审计记录",
		"`nvd.nist.gov`",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("MLPS report missing %q:\n%s", want, md)
		}
	}

	std := Markdown(Input{
		Title:       "Standard Test",
		Goal:        "Check outbound section",
		GeneratedAt: time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC),
		OutboundLogs: []db.OutboundLog{
			{
				Source:     "proxy",
				Protocol:   "https",
				TargetHost: "api.github.com",
				TargetPort: 443,
				HitCount:   2,
				Purpose:    "HTTP/HTTPS proxy egress",
				FirstSeen:  time.Date(2026, 11, 17, 11, 50, 0, 0, time.UTC),
				LastSeen:   time.Date(2026, 11, 17, 11, 51, 0, 0, time.UTC),
			},
		},
	})
	if !strings.Contains(std, "Outbound / External Connections Audit") || !strings.Contains(std, "`api.github.com`") {
		t.Errorf("standard report missing outbound section:\n%s", std)
	}
}
