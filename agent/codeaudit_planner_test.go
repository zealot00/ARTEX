package agent

import (
	"strings"
	"testing"
)

func TestCodeAuditPlannerAndWorkerSpecialization(t *testing.T) {
	seeds := BuiltinPromptSeeds()

	planner := seeds["planner"]
	for _, want := range []string{
		"Code Audit & White-Box / Gray-Box Vulnerability Hunting",
		"Attack-Surface & Shared-Defense Inventory",
		"Partitioned Source-to-Sink & Sink-to-Source Parallel Hunts",
		"Dangerous Sink Backtracking",
		"Gray-Box Live Verification",
		"authz_replay",
		"race_probe",
	} {
		if !strings.Contains(planner, want) {
			t.Errorf("plannerDefaultTmpl missing code-audit specialization clause %q", want)
		}
	}

	worker := seeds["worker"]
	for _, want := range []string{
		"Source Code Audit & White-Box Hunting",
		"file:line",
		"authz_replay",
		"race_probe",
	} {
		if !strings.Contains(worker, want) {
			t.Errorf("workerDefaultTmpl missing code-audit clause %q", want)
		}
	}

	pentest := seeds["pentest"]
	for _, want := range []string{
		"white-box/gray-box source audits",
		"authz_replay",
		"race_probe",
	} {
		if !strings.Contains(pentest, want) {
			t.Errorf("pentestDefaultTmpl missing code-audit/bizprobe clause %q", want)
		}
	}
}
