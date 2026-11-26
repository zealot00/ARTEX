package report

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
)

// MLPSInput bundles task metadata, compliance checks, asset counts, and findings
// for rendering a structured MLPS 2.0 (等保 2.0) penetration test report.
type MLPSInput struct {
	TaskID            string
	ExternalRef       string
	Title             string
	Goal              string
	ComplianceProfile string
	ProdSafeMode      bool
	GeneratedAt       time.Time
	AssetCounts       map[string]int
	Checks            []db.TaskCheck
	Findings          []*db.Node
	OutboundLogs      []db.OutboundLog
	SolverState       *db.SolverStateRecord
	BlackboardEntries []db.BlackboardEntry
}

var checkStatusLabel = map[string]string{
	db.CheckStatusPassed:  "通过 (已测无漏洞)",
	db.CheckStatusFailed:  "未通过 (存在风险)",
	db.CheckStatusNA:      "不适用 (N/A)",
	db.CheckStatusBlocked: "受阻/未完成",
	db.CheckStatusPending: "待测试",
}

// MLPSMarkdown renders a structured MLPS 2.0 compliance penetration test report,
// including positive findings, negative-test compliance matrix, and safety baseline status.
func MLPSMarkdown(in MLPSInput) string {
	var b strings.Builder
	sum := db.SummarizeTaskChecks(in.Checks)

	fmt.Fprintf(&b, "# 等级保护渗透测试报告（MLPS 2.0） — %s\n\n", nz(in.Title, "未命名任务"))
	fmt.Fprintf(&b, "## 1. 基本信息与授权范围声明\n\n")
	fmt.Fprintf(&b, "- **任务编号**：`%s`\n", nz(in.TaskID, "-"))
	if strings.TrimSpace(in.ExternalRef) != "" {
		fmt.Fprintf(&b, "- **关联工单号**：`%s`\n", in.ExternalRef)
	}
	fmt.Fprintf(&b, "- **测评目标**：%s\n", nz(in.Goal, "（未填写）"))
	fmt.Fprintf(&b, "- **合规基线**：`%s`\n", nz(in.ComplianceProfile, "mlps"))
	fmt.Fprintf(&b, "- **生产安全基线模式**：%s\n", map[bool]string{true: "已启用（低并发限速 / 禁止 DoS 与破坏性操作）", false: "未启用"}[in.ProdSafeMode])
	fmt.Fprintf(&b, "- **报告生成时间**：%s\n", in.GeneratedAt.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(&b, "- **授权与边界声明**：本次渗透测试仅针对任务声明授权范围内的资产执行，严禁超出授权边界或执行影响业务连续性的破坏性操作。\n\n")

	fmt.Fprintf(&b, "## 2. 测试覆盖与风险概览\n\n")
	fmt.Fprintf(&b, "- **检查项总数**：%d（通过/阴性留痕 **%d**，检出风险 **%d**，不适用 **%d**，受阻 **%d**，待测 **%d**）\n",
		sum.Total, sum.Passed, sum.Failed, sum.NA, sum.Blocked, sum.Pending)
	fmt.Fprintf(&b, "- **已确认漏洞数**：**%d**\n", len(in.Findings))
	if len(in.AssetCounts) > 0 {
		fmt.Fprintf(&b, "- **覆盖资产统计**：")
		types := make([]string, 0, len(in.AssetCounts))
		for t := range in.AssetCounts {
			types = append(types, t)
		}
		sort.Strings(types)
		for i, t := range types {
			if i > 0 {
				b.WriteString("，")
			}
			fmt.Fprintf(&b, "%s %d", t, in.AssetCounts[t])
		}
		b.WriteString("\n")
	}
	b.WriteString("\n")

	fmt.Fprintf(&b, "## 3. 等保渗透测试控制点矩阵（含阴性测试留痕）\n\n")
	if len(in.Checks) == 0 {
		b.WriteString("_暂无检查项记录。_\n\n")
	} else {
		b.WriteString("| 编号 | 等保控制域 | 检查项 | 目标 | 结论 | 实测证据摘要 | 记录方 |\n")
		b.WriteString("| :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n")
		for _, c := range in.Checks {
			label := checkStatusLabel[c.Status]
			if label == "" {
				label = c.Status
			}
			ev := escapeMDCell(clipRunes(nz(c.Evidence, c.Notes), 120))
			if ev == "" {
				ev = "-"
			}
			fmt.Fprintf(&b, "| `%s` | %s | %s | %s | %s | %s | %s |\n",
				escapeMDCell(c.CheckCode),
				escapeMDCell(c.Domain),
				escapeMDCell(c.Title),
				escapeMDCell(nz(c.Target, "全局")),
				label,
				ev,
				escapeMDCell(nz(c.TestedBy, "-")),
			)
		}
		b.WriteString("\n")
	}

	fmt.Fprintf(&b, "## 4. 已检出安全漏洞详情\n\n")
	if len(in.Findings) == 0 {
		b.WriteString("_本次测试未检出已确认的安全漏洞。_\n\n")
	} else {
		fs := make([]findingView, 0, len(in.Findings))
		for _, n := range in.Findings {
			fs = append(fs, parseFinding(n))
		}
		sort.SliceStable(fs, func(i, j int) bool { return sevRank[fs[i].Severity] < sevRank[fs[j].Severity] })
		for i, f := range fs {
			fmt.Fprintf(&b, "### 4.%d [%s] %s\n\n", i+1, strings.ToUpper(nz(f.Severity, "info")), nz(f.Name, nz(f.VulnClass, "未分类漏洞")))
			fmt.Fprintf(&b, "%s\n\n", nz(f.Summary, ""))
			if f.PoC != "" {
				fmt.Fprintf(&b, "**PoC / 验证证据：**\n\n```\n%s\n```\n\n", f.PoC)
			}
		}
	}

	fmt.Fprintf(&b, "## 5. 任务执行期间外联审计记录（用于上层流量核查自证）\n\n")
	if len(in.OutboundLogs) == 0 {
		b.WriteString("_本次任务执行期间未记录到外部外联请求。_\n\n")
	} else {
		b.WriteString("| 外部目标 Host | 端口 | 协议 | 来源 | 次数 | 首次时间 | 最近时间 | 用途说明 | URL 摘要 |\n")
		b.WriteString("| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n")
		for _, o := range in.OutboundLogs {
			fmt.Fprintf(&b, "| `%s` | %d | `%s` | `%s` | %d | %s | %s | %s | %s |\n",
				escapeMDCell(o.TargetHost),
				o.TargetPort,
				escapeMDCell(o.Protocol),
				escapeMDCell(o.Source),
				o.HitCount,
				o.FirstSeen.Format("2006-01-02 15:04:05"),
				o.LastSeen.Format("2006-01-02 15:04:05"),
				escapeMDCell(nz(o.Purpose, "-")),
				escapeMDCell(clipRunes(nz(o.URLPreview, "-"), 96)),
			)
		}
		b.WriteString("\n")
	}

	fmt.Fprintf(&b, "## 6. 深度求解覆盖、已剪枝机制与黑板未闭合线索审计\n\n")
	if in.SolverState != nil {
		label := in.SolverState.CurrentTierLabel
		if label == "" {
			label = db.SolverTierName(in.SolverState.CurrentTier)
		}
		fmt.Fprintf(&b, "- **「唯一求解」最高推进阶梯**：`%s`（%d/5 阶）\n", escapeMDCell(label), in.SolverState.CurrentTier)
		fmt.Fprintf(&b, "- **已实证剪枝的攻击机制数**：**%d**\n\n", len(in.SolverState.PrunedMechanisms))
		if len(in.SolverState.PrunedMechanisms) > 0 {
			b.WriteString("| 目标 | 已剪枝机制 | 阶梯 | 排除依据 | 实证引用 |\n")
			b.WriteString("| :--- | :--- | :--- | :--- | :--- |\n")
			for _, pm := range in.SolverState.PrunedMechanisms {
				fmt.Fprintf(&b, "| `%s` | `%s` | L%d | %s | `%s` |\n",
					escapeMDCell(pm.Target),
					escapeMDCell(pm.Mechanism),
					pm.Tier,
					escapeMDCell(clipRunes(nz(pm.Reason, "-"), 100)),
					escapeMDCell(nz(pm.EvidenceRef, "-")),
				)
			}
			b.WriteString("\n")
		}
	}
	if len(in.BlackboardEntries) == 0 {
		b.WriteString("_本次任务无未闭合的共享黑板线索、搁置接口或隔离诱饵记录。_\n\n")
	} else {
		b.WriteString("| 类型 | 确定性状态 | 目标 | 主题/线索摘要 | 前置条件标签 | 证据引用 |\n")
		b.WriteString("| :--- | :--- | :--- | :--- | :--- | :--- |\n")
		for _, e := range in.BlackboardEntries {
			fmt.Fprintf(&b, "| `%s` | `%s` | `%s` | %s | `%s` | `%s` |\n",
				escapeMDCell(e.Kind),
				escapeMDCell(e.EpistemicState),
				escapeMDCell(nz(e.Target, "-")),
				escapeMDCell(clipRunes(e.Topic, 90)),
				escapeMDCell(nz(e.PreconditionTag, "-")),
				escapeMDCell(nz(e.EvidenceRef, "-")),
			)
		}
		b.WriteString("\n")
	}

	fmt.Fprintf(&b, "## 7. 整改与复测建议\n\n")
	fmt.Fprintf(&b, "1. 针对上述“未通过”控制点与高/中危漏洞，按业务影响优先级实施整改并回归验证。\n")
	fmt.Fprintf(&b, "2. 对仍处于“待测试”、“受阻”或黑板中标记为 `deferred_endpoint`（因缺少凭据/前置条件暂缓）的接口，建议在具备测试窗口与对应角色凭据后补充专项验证。\n")
	fmt.Fprintf(&b, "3. 整改完成后，可通过 ARTEX 复测流程对相应 Finding 执行回归验证并重新导出报告留档。\n")
	return b.String()
}

func escapeMDCell(s string) string {
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "|", "\\|")
	return strings.TrimSpace(s)
}

func clipRunes(s string, max int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) <= max {
		return string(r)
	}
	return string(r[:max]) + "…"
}
