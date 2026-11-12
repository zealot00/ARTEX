package agent

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"

	"github.com/Autumn-27/norma/llm"
)

const (
	envLLMHostAllowlist      = "ARTEX_LLM_HOST_ALLOWLIST"
	envLLMRequireBaseURL     = "ARTEX_LLM_REQUIRE_BASE_URL"
	envLLMDisableEnvFallback = "ARTEX_LLM_DISABLE_ENV_FALLBACK"
	envDisableWebSearch      = "ARTEX_DISABLE_WEB_SEARCH"
)

// EndpointPolicy controls which upstream LLM endpoints ARTEX is allowed to dial.
// When AllowedHosts is non-empty, RequireBaseURL is forced on so an empty
// BaseURL can never silently fall back to public vendor endpoints or SDK env vars.
type EndpointPolicy struct {
	RequireBaseURL bool
	AllowedHosts   []string
}

func isTruthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "on", "yes":
		return true
	default:
		return false
	}
}

// CurrentEndpointPolicy builds the active LLM endpoint policy from environment variables.
func CurrentEndpointPolicy() EndpointPolicy {
	raw := strings.TrimSpace(os.Getenv(envLLMHostAllowlist))
	var allowed []string
	if raw != "" {
		for _, item := range strings.Split(raw, ",") {
			if rule := strings.TrimSpace(item); rule != "" {
				allowed = append(allowed, rule)
			}
		}
	}
	require := len(allowed) > 0 || isTruthy(os.Getenv(envLLMRequireBaseURL))
	return EndpointPolicy{
		RequireBaseURL: require,
		AllowedHosts:   allowed,
	}
}

// WebSearchDisabledByEnv reports whether external web search egress is disabled
// by environment policy (ARTEX_DISABLE_WEB_SEARCH).
func WebSearchDisabledByEnv() bool {
	return isTruthy(os.Getenv(envDisableWebSearch))
}

// EnvFallbackDisabledByEnv reports whether automatic startup LLM fallback to
// process environment variables is disabled (ARTEX_LLM_DISABLE_ENV_FALLBACK).
func EnvFallbackDisabledByEnv() bool {
	return isTruthy(os.Getenv(envLLMDisableEnvFallback))
}

// ValidateProxyURL parses and validates an explicit LLM/discovery proxy URL.
// Empty input returns (nil, nil), meaning direct connection without env proxy fallback.
func ValidateProxyURL(proxy string) (*url.URL, error) {
	proxy = strings.TrimSpace(proxy)
	if proxy == "" {
		return nil, nil
	}
	u, err := url.Parse(proxy)
	if err != nil {
		return nil, fmt.Errorf("llm: invalid proxy %q: %w", proxy, err)
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https", "socks5":
	case "":
		return nil, fmt.Errorf("llm: proxy %q missing scheme (use http://, https:// or socks5://)", proxy)
	default:
		return nil, fmt.Errorf("llm: unsupported proxy scheme %q (use http, https or socks5)", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("llm: proxy %q missing host", proxy)
	}
	return u, nil
}

// RejectLLMRedirect blocks HTTP 30x redirects on LLM and model-discovery clients
// so credentials (including custom x-api-key headers) and prompt bodies never
// leak to an unexpected third-party host via redirect.
func RejectLLMRedirect(req *http.Request, _ []*http.Request) error {
	host := ""
	if req != nil && req.URL != nil {
		host = req.URL.Host
	}
	return fmt.Errorf("llm: HTTP redirects are disabled for LLM requests (refused redirect to %q)", host)
}

// ValidateEndpoint checks format/baseURL against CurrentEndpointPolicy.
func ValidateEndpoint(format llm.Format, baseURL string) error {
	return CurrentEndpointPolicy().Validate(format, baseURL)
}

// Validate checks format/baseURL against this EndpointPolicy.
func (p EndpointPolicy) Validate(format llm.Format, baseURL string) error {
	trimmed := strings.TrimSpace(baseURL)
	if trimmed == "" {
		if p.RequireBaseURL {
			return fmt.Errorf("llm: base_url is required by endpoint policy for format %q (refusing public/env fallback)", format)
		}
		return nil
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return fmt.Errorf("llm: invalid base_url %q: %w", trimmed, err)
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	default:
		return fmt.Errorf("llm: unsupported base_url scheme %q (use http or https)", u.Scheme)
	}
	if u.Hostname() == "" {
		return fmt.Errorf("llm: base_url %q missing host", trimmed)
	}
	if len(p.AllowedHosts) > 0 && !matchesEndpointAllowlist(u, p.AllowedHosts) {
		return fmt.Errorf("llm: base_url host %q is not in %s", u.Host, envLLMHostAllowlist)
	}
	return nil
}

func matchesEndpointAllowlist(u *url.URL, rules []string) bool {
	host := strings.ToLower(u.Hostname())
	hostPort := strings.ToLower(u.Host)
	addr, ipErr := netip.ParseAddr(host)

	for _, rawRule := range rules {
		rule := strings.ToLower(strings.TrimSpace(rawRule))
		if rule == "" {
			continue
		}
		// CIDR rule (e.g. 10.0.0.0/8, 127.0.0.1/32)
		if prefix, err := netip.ParsePrefix(rule); err == nil {
			if ipErr == nil && prefix.Contains(addr) {
				return true
			}
			continue
		}
		// Exact IP rule
		if ruleAddr, err := netip.ParseAddr(rule); err == nil {
			if ipErr == nil && addr == ruleAddr {
				return true
			}
			continue
		}
		// Domain wildcard suffix (.corp.internal or *.corp.internal)
		if strings.HasPrefix(rule, "*.") || strings.HasPrefix(rule, ".") {
			suffix := strings.TrimPrefix(rule, "*")
			if !strings.HasPrefix(suffix, ".") {
				suffix = "." + suffix
			}
			if strings.HasSuffix(host, suffix) || host == strings.TrimPrefix(suffix, ".") {
				return true
			}
			continue
		}
		// Rule with explicit port (host:port or [ipv6]:port)
		if rHost, rPort, err := net.SplitHostPort(rule); err == nil {
			reqPort := u.Port()
			if reqPort == "" {
				if strings.EqualFold(u.Scheme, "https") {
					reqPort = "443"
				} else if strings.EqualFold(u.Scheme, "http") {
					reqPort = "80"
				}
			}
			rHost = strings.Trim(strings.ToLower(rHost), "[]")
			if host == rHost && reqPort == rPort {
				return true
			}
			continue
		}
		// Host-only exact match (matches regardless of port)
		if host == strings.Trim(rule, "[]") || hostPort == rule {
			return true
		}
	}
	return false
}
