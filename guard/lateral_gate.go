package guard

import (
	"regexp"
	"strings"
)

var lateralCommandRules = []prodSafeRule{
	{
		re:     regexp.MustCompile(`(?i)\b(?:proxychains4?|chisel|ligolo(?:-ng|-agent|-proxy)?|socat)\b`),
		reason: "lateral movement is gated until a foothold vulnerability is confirmed and approved",
	},
	{
		re:     regexp.MustCompile(`(?i)\bssh\b.*\s-(?:[a-zA-Z]*[DLR])\b`),
		reason: "SSH tunnel/pivot (-D/-L/-R) is gated until lateral movement is approved",
	},
	{
		re:     regexp.MustCompile(`(?i)\b(?:impacket-\S+|crackmapexec|netexec|nxc|evil-winrm)\b`),
		reason: "internal lateral-movement tool is gated until lateral movement is approved",
	},
}

// CheckLateralCommand inspects a command for pivoting, tunneling, or internal
// lateral-movement tooling that must wait for foothold confirmation/approval.
func CheckLateralCommand(cmd string) (string, bool) {
	trimmed := strings.TrimSpace(cmd)
	if trimmed == "" {
		return "", false
	}
	for _, rule := range lateralCommandRules {
		if rule.re.MatchString(trimmed) {
			return rule.reason, true
		}
	}
	return "", false
}
