package guard

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/intercept"
)

type fenceRuleKind int

const (
	fenceKindCIDR fenceRuleKind = iota
	fenceKindIP
	fenceKindDomain
	fenceKindWildcard
	fenceKindURL
)

// FenceRule is one compiled electronic-fence allow rule.
type FenceRule struct {
	Raw        string
	kind       fenceRuleKind
	prefix     netip.Prefix
	addr       netip.Addr
	host       string
	port       int
	scheme     string
	pathPrefix string
}

// ParseFenceRules validates and compiles raw electronic-fence entries.
// Supported forms: CIDR ("10.10.0.0/16"), IP ("192.168.1.5" or "192.168.1.5:8080"),
// domain ("app.corp.local", "app.corp.local:8443"), wildcard domain ("*.corp.local",
// ".corp.local"), and URL ("https://app.corp.local:8443/api").
func ParseFenceRules(raw []string) ([]FenceRule, error) {
	out := make([]FenceRule, 0, len(raw))
	seen := make(map[string]bool, len(raw))
	for _, entry := range raw {
		s := strings.TrimSpace(entry)
		if s == "" {
			continue
		}
		if seen[strings.ToLower(s)] {
			continue
		}
		seen[strings.ToLower(s)] = true
		r, err := parseOneFenceRule(s)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

func parseOneFenceRule(s string) (FenceRule, error) {
	lower := strings.ToLower(s)
	// URL rule
	if strings.Contains(lower, "://") {
		u, err := url.Parse(s)
		if err != nil || u.Hostname() == "" {
			return FenceRule{}, fmt.Errorf("invalid fence URL %q", s)
		}
		scheme := strings.ToLower(u.Scheme)
		if scheme != "http" && scheme != "https" {
			return FenceRule{}, fmt.Errorf("unsupported fence URL scheme %q (use http or https)", u.Scheme)
		}
		port := 0
		if p := u.Port(); p != "" {
			n, err := strconv.Atoi(p)
			if err != nil || n < 1 || n > 65535 {
				return FenceRule{}, fmt.Errorf("invalid port in fence URL %q", s)
			}
			port = n
		}
		pathPrefix := strings.TrimRight(u.EscapedPath(), "/")
		if pathPrefix == "" {
			pathPrefix = "/"
		}
		return FenceRule{
			Raw:        s,
			kind:       fenceKindURL,
			scheme:     scheme,
			host:       strings.ToLower(u.Hostname()),
			port:       port,
			pathPrefix: pathPrefix,
		}, nil
	}

	// CIDR rule
	if pfx, err := netip.ParsePrefix(s); err == nil {
		return FenceRule{Raw: s, kind: fenceKindCIDR, prefix: pfx.Masked()}, nil
	}

	// Bare IP
	if addr, err := netip.ParseAddr(s); err == nil {
		return FenceRule{Raw: s, kind: fenceKindIP, addr: addr}, nil
	}

	// Split optional :port
	hostPart, port := s, 0
	if h, p, err := net.SplitHostPort(s); err == nil {
		n, perr := strconv.Atoi(p)
		if perr != nil || n < 1 || n > 65535 {
			return FenceRule{}, fmt.Errorf("invalid port in fence rule %q", s)
		}
		hostPart, port = strings.Trim(h, "[]"), n
	}
	if addr, err := netip.ParseAddr(hostPart); err == nil {
		return FenceRule{Raw: s, kind: fenceKindIP, addr: addr, port: port}, nil
	}

	hostLower := strings.ToLower(strings.TrimSuffix(hostPart, "."))
	if strings.HasPrefix(hostLower, "*.") || strings.HasPrefix(hostLower, ".") {
		suffix := strings.TrimPrefix(hostLower, "*")
		if !strings.HasPrefix(suffix, ".") {
			suffix = "." + suffix
		}
		if len(suffix) < 3 {
			return FenceRule{}, fmt.Errorf("invalid wildcard fence domain %q", s)
		}
		return FenceRule{Raw: s, kind: fenceKindWildcard, host: suffix, port: port}, nil
	}

	if hostLower == "" || strings.ContainsAny(hostLower, " /\\*?@") {
		return FenceRule{}, fmt.Errorf("invalid fence rule %q", s)
	}
	return FenceRule{Raw: s, kind: fenceKindDomain, host: hostLower, port: port}, nil
}

// CheckFenceTarget checks whether target t is permitted by rules (or exemptions).
func CheckFenceTarget(rules []FenceRule, exemptions []string, t intercept.Target) (bool, string) {
	if isExemptTarget(exemptions, t) {
		return true, ""
	}
	if len(rules) == 0 {
		return false, fmt.Sprintf("target %s rejected: electronic fence is enabled with no authorized rules", t.String())
	}
	for _, r := range rules {
		if r.matchesTarget(t) {
			return true, ""
		}
	}
	return false, fmt.Sprintf("target %s is outside the authorized electronic fence", t.String())
}

func (r FenceRule) matchesTarget(t intercept.Target) bool {
	if r.port > 0 && t.Port != r.port {
		return false
	}
	switch t.Kind {
	case "cidr":
		pfx, err := netip.ParsePrefix(t.Host)
		if err != nil {
			return false
		}
		pfx = pfx.Masked()
		switch r.kind {
		case fenceKindCIDR:
			return pfx.Bits() >= r.prefix.Bits() && r.prefix.Contains(pfx.Addr())
		case fenceKindIP:
			return pfx.IsSingleIP() && pfx.Addr() == r.addr
		}
	case "ip":
		addr, err := netip.ParseAddr(t.Host)
		if err != nil {
			return false
		}
		switch r.kind {
		case fenceKindCIDR:
			return r.prefix.Contains(addr)
		case fenceKindIP:
			return addr == r.addr
		case fenceKindDomain, fenceKindURL:
			if ruleAddr, err := netip.ParseAddr(r.host); err == nil {
				return addr == ruleAddr
			}
		}
	case "domain":
		h := strings.ToLower(strings.TrimSuffix(t.Host, "."))
		switch r.kind {
		case fenceKindDomain, fenceKindURL:
			return h == r.host
		case fenceKindWildcard:
			return strings.HasSuffix(h, r.host) || h == strings.TrimPrefix(r.host, ".")
		}
	}
	return false
}

func (r FenceRule) matchesURL(u *url.URL) bool {
	if u == nil {
		return false
	}
	t, ok := intercept.NormalizeTarget(u.String())
	if !ok {
		return false
	}
	if !r.matchesTarget(t) {
		return false
	}
	if r.kind == fenceKindURL {
		if !strings.EqualFold(u.Scheme, r.scheme) {
			return false
		}
		if r.pathPrefix != "/" {
			p := u.EscapedPath()
			if p == "" {
				p = "/"
			}
			if p != r.pathPrefix && !strings.HasPrefix(p, r.pathPrefix+"/") {
				return false
			}
		}
	}
	return true
}

func isExemptTarget(exemptions []string, t intercept.Target) bool {
	for _, ex := range exemptions {
		ex = strings.TrimSpace(ex)
		if ex == "" {
			continue
		}
		et, ok := intercept.NormalizeTarget(ex)
		if !ok {
			continue
		}
		if et.Kind == t.Kind && et.Host == t.Host && (et.Port == 0 || et.Port == t.Port) {
			return true
		}
	}
	return false
}
