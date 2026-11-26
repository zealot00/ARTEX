// Package report renders a deliverable Markdown report from the exploration
// graph: confirmed findings (with severity/evidence) (docs §15 P5).
package report

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
)

// Input bundles what the report needs.
type Input struct {
	Title             string
	Goal              string
	GeneratedAt       time.Time
	AssetCounts       map[string]int
	Findings          []*db.Node
	OutboundLogs      []db.OutboundLog
	SolverState       *db.SolverStateRecord
	BlackboardEntries []db.BlackboardEntry
}

type findingView struct {
	VulnClass string
	Name      string
	Severity  string
	Summary   string
	PoC       string
}

func parseFinding(n *db.Node) findingView {
	var p struct {
		VulnClass string `json:"vulnclass"`
		Name      string `json:"name"`
		Severity  string `json:"severity"`
		Summary   string `json:"summary"`
		Evidence  struct {
			PoC string `json:"poc"`
		} `json:"evidence"`
	}
	_ = json.Unmarshal(n.Payload, &p)
	return findingView{p.VulnClass, p.Name, p.Severity, p.Summary, p.Evidence.PoC}
}

var sevRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "": 4}

// Markdown renders the report.
func Markdown(in Input) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Penetration Test Report — %s\n\n", nz(in.Title, "Unnamed task"))
	fmt.Fprintf(&b, "- **Task goal**: %s\n", nz(in.Goal, "(unspecified)"))
	fmt.Fprintf(&b, "- **Generated at**: %s\n\n", in.GeneratedAt.Format("2006-01-02 15:04:05"))

	// summary
	fmt.Fprintf(&b, "## Summary\n\n")
	fmt.Fprintf(&b, "- Confirmed findings: **%d**\n", len(in.Findings))
	fmt.Fprintf(&b, "- Assets: ")
	var types []string
	for t := range in.AssetCounts {
		types = append(types, t)
	}
	sort.Strings(types)
	for i, t := range types {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%s %d", t, in.AssetCounts[t])
	}
	b.WriteString("\n\n")

	// findings
	fmt.Fprintf(&b, "## Findings\n\n")
	if len(in.Findings) == 0 {
		b.WriteString("_No vulnerabilities confirmed this time._\n\n")
	} else {
		fs := make([]findingView, 0, len(in.Findings))
		for _, n := range in.Findings {
			fs = append(fs, parseFinding(n))
		}
		sort.SliceStable(fs, func(i, j int) bool { return sevRank[fs[i].Severity] < sevRank[fs[j].Severity] })
		for i, f := range fs {
			fmt.Fprintf(&b, "### %d. [%s] %s\n\n", i+1, strings.ToUpper(nz(f.Severity, "info")), nz(f.Name, nz(f.VulnClass, "Uncategorized")))
			fmt.Fprintf(&b, "%s\n\n", nz(f.Summary, ""))
			if f.PoC != "" {
				fmt.Fprintf(&b, "**PoC / Evidence:**\n\n```\n%s\n```\n\n", f.PoC)
			}
		}
	}

	fmt.Fprintf(&b, "## Outbound / External Connections Audit\n\n")
	if len(in.OutboundLogs) == 0 {
		b.WriteString("_No external outbound connections were recorded during this task._\n\n")
	} else {
		b.WriteString("| Target Host | Port | Protocol | Source | Hits | First Seen | Last Seen | Purpose | Sample URL |\n")
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

	fmt.Fprintf(&b, "## Focused Solver Depth, Pruned Mechanisms & Blackboard Audit\n\n")
	if in.SolverState != nil {
		label := in.SolverState.CurrentTierLabel
		if label == "" {
			label = db.SolverTierName(in.SolverState.CurrentTier)
		}
		fmt.Fprintf(&b, "- **Highest Technique Escalation Stage**: `%s` (%d/5)\n", escapeMDCell(label), in.SolverState.CurrentTier)
		fmt.Fprintf(&b, "- **Pruned Mechanisms (Negative Proof)**: **%d**\n\n", len(in.SolverState.PrunedMechanisms))
		if len(in.SolverState.PrunedMechanisms) > 0 {
			b.WriteString("| Target | Pruned Mechanism | Tier | Reason | Evidence Ref |\n")
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
		b.WriteString("_No unresolved blackboard leads, deferred surfaces, or quarantined deception artifacts were recorded._\n\n")
	} else {
		b.WriteString("### Shared Uncertainty Blackboard Ledger (Deferred Surfaces, Hypotheses & Quarantined Decoys)\n\n")
		b.WriteString("| Kind | State | Target | Topic | Precondition | Evidence Ref |\n")
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

	return b.String()
}

func nz(s, d string) string {
	if strings.TrimSpace(s) == "" {
		return d
	}
	return s
}
