package db

import "testing"

func TestMLPSBaselineChecksAndSummary(t *testing.T) {
	tpls := MLPSBaselineChecks()
	if len(tpls) != 12 {
		t.Fatalf("expected 12 MLPS baseline checks, got %d", len(tpls))
	}
	seen := map[string]bool{}
	for _, tpl := range tpls {
		if tpl.Code == "" || tpl.Domain == "" || tpl.Title == "" {
			t.Fatalf("incomplete template: %+v", tpl)
		}
		if seen[tpl.Code] {
			t.Fatalf("duplicate check_code %q", tpl.Code)
		}
		seen[tpl.Code] = true
	}

	if _, err := NormalizeCheckStatus("passed"); err != nil {
		t.Fatalf("valid status rejected: %v", err)
	}
	if _, err := NormalizeCheckStatus("invalid"); err == nil {
		t.Fatal("expected invalid status to error")
	}

	sum := SummarizeTaskChecks([]TaskCheck{
		{Status: CheckStatusPassed},
		{Status: CheckStatusPassed},
		{Status: CheckStatusFailed},
		{Status: CheckStatusNA},
		{Status: CheckStatusBlocked},
		{Status: CheckStatusPending},
	})
	if sum.Total != 6 || sum.Passed != 2 || sum.Failed != 1 || sum.NA != 1 || sum.Blocked != 1 || sum.Pending != 1 {
		t.Fatalf("unexpected summary: %+v", sum)
	}
}
