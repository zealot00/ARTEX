package server

import "testing"

func TestShouldRecordOutbound(t *testing.T) {
	task := &Task{
		ID:         "10",
		FenceRules: []string{"https://app.corp.local:8443", "10.10.0.0/16"},
	}

	cases := []struct {
		host string
		want bool
	}{
		{"127.0.0.1", false},
		{"localhost", false},
		{"10.10.5.12", false},
		{"192.168.1.10", false},
		{"app.corp.local", false},
		{"nvd.nist.gov", true},
		{"api.github.com", true},
		{"8.8.8.8", true},
	}

	for _, tc := range cases {
		if got := shouldRecordOutbound(task, tc.host); got != tc.want {
			t.Errorf("shouldRecordOutbound(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}
