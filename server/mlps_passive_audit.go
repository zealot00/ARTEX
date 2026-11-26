package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/textclean"
	actool "github.com/Autumn-27/norma/tool"
)

// LateralSegmentationRisk describes one passive MLPS 2.0 network-boundary / lateral-defense finding.
type LateralSegmentationRisk struct {
	Category    string `json:"category"`
	Severity    string `json:"severity"`
	CheckCode   string `json:"check_code"`
	Target      string `json:"target"`
	Detail      string `json:"detail"`
	Remediation string `json:"remediation"`
}

// LateralSegmentationReport summarizes passive MLPS 2.0 lateral-defense compliance posture
// derived strictly from already-recorded asset inventory (zero active scanning or exploitation).
type LateralSegmentationReport struct {
	TaskID            string                    `json:"task_id"`
	TotalAssets       int                       `json:"total_assets"`
	DistinctSubnets24 []string                  `json:"distinct_subnets_24"`
	ExposedHighRisk   int                       `json:"exposed_high_risk_ports"`
	ZoneViolations    int                       `json:"zone_isolation_violations"`
	Verdict           string                    `json:"verdict"` // passed | failed
	Risks             []LateralSegmentationRisk `json:"risks"`
	Summary           string                    `json:"summary"`
}

type lateralPortRule struct {
	service     string
	severity    string
	checkCode   string
	zone        string // mgmt | data | control | ad | win
	remediation string
}

var lateralHighRiskPorts = map[int]lateralPortRule{
	22:    {service: "SSH", severity: "medium", checkCode: "NET-BOUNDARY", zone: "mgmt", remediation: "Restrict SSH to bastion/jump-host CIDR via firewall ACL and require key-based MFA."},
	23:    {service: "Telnet", severity: "high", checkCode: "NET-TLS", zone: "mgmt", remediation: "Disable plaintext Telnet and migrate administration to SSH over management VLAN."},
	88:    {service: "Kerberos", severity: "medium", checkCode: "AD-DIR", zone: "ad", remediation: "Isolate Domain Controller ports from DMZ/application segments and enforce Kerberos AES."},
	389:   {service: "LDAP", severity: "high", checkCode: "AD-DIR", zone: "ad", remediation: "Enforce LDAPS (636) with channel binding/signing and block LDAP access from non-domain zones."},
	445:   {service: "SMB", severity: "high", checkCode: "WIN-SVC", zone: "win", remediation: "Block TCP/445 across network zone boundaries, enforce SMB signing, and disable SMBv1."},
	1433:  {service: "MSSQL", severity: "high", checkCode: "SVC-UNAUTH", zone: "data", remediation: "Place database tier in an isolated data VLAN accessible only from authorized app-tier IPs."},
	1521:  {service: "Oracle", severity: "high", checkCode: "SVC-UNAUTH", zone: "data", remediation: "Restrict Oracle listener to dedicated app-server allowlist and enable network encryption."},
	2375:  {service: "Docker API (plaintext)", severity: "critical", checkCode: "SVC-UNAUTH", zone: "control", remediation: "Disable unencrypted TCP/2375 immediately; bind Docker daemon to Unix socket or mTLS 2376."},
	3306:  {service: "MySQL", severity: "high", checkCode: "SVC-UNAUTH", zone: "data", remediation: "Restrict MySQL to internal data-zone ACLs and disallow wildcard (%) remote root grants."},
	3389:  {service: "RDP", severity: "high", checkCode: "WIN-SVC", zone: "mgmt", remediation: "Remove direct RDP exposure; enforce bastion/VPN + NLA (Network Level Authentication)."},
	5432:  {service: "PostgreSQL", severity: "high", checkCode: "SVC-UNAUTH", zone: "data", remediation: "Restrict PostgreSQL via pg_hba.conf + VLAN ACLs and enforce TLS/scram-sha-256."},
	5985:  {service: "WinRM HTTP", severity: "high", checkCode: "WIN-SVC", zone: "mgmt", remediation: "Restrict WinRM to dedicated management subnet and enforce HTTPS (5986) with Kerberos."},
	6379:  {service: "Redis", severity: "critical", checkCode: "SVC-UNAUTH", zone: "data", remediation: "Bind Redis to internal interface only, enable ACL/strong AUTH, and isolate from web/DMZ zones."},
	6443:  {service: "Kubernetes API", severity: "high", checkCode: "NET-BOUNDARY", zone: "control", remediation: "Restrict K8s API server to control-plane CIDR and enforce RBAC + audit logging."},
	8848:  {service: "Nacos", severity: "high", checkCode: "APP-API", zone: "control", remediation: "Isolate Nacos config/registry center inside internal governance zone and enable auth."},
	9200:  {service: "Elasticsearch", severity: "high", checkCode: "SVC-UNAUTH", zone: "data", remediation: "Enable X-Pack/TLS auth and block direct access to TCP/9200 from application/external zones."},
	10250: {service: "Kubelet API", severity: "critical", checkCode: "SVC-UNAUTH", zone: "control", remediation: "Disable anonymous Kubelet auth and block TCP/10250 from non-control-plane hosts."},
	27017: {service: "MongoDB", severity: "high", checkCode: "SVC-UNAUTH", zone: "data", remediation: "Enable MongoDB authorization + TLS and isolate port 27017 inside the data zone."},
}

var webTierPorts = map[int]bool{80: true, 443: true, 8000: true, 8080: true, 8443: true}

// EvaluateLateralSegmentation performs a purely passive MLPS 2.0 lateral-defense & network-segmentation
// assessment over an already-recorded slice of assets (no active network I/O).
func EvaluateLateralSegmentation(taskID string, assets []*db.Asset) LateralSegmentationReport {
	subnetSet := map[string]bool{}
	hostPorts := map[string]map[int]bool{}
	subnetZones := map[string]map[string]bool{}

	recordHostPort := func(host string, port int) {
		host = strings.TrimSpace(host)
		if host == "" {
			return
		}
		if ip, err := netip.ParseAddr(host); err == nil && ip.Is4() {
			b := ip.As4()
			sub := fmt.Sprintf("%d.%d.%d.0/24", b[0], b[1], b[2])
			subnetSet[sub] = true
			if subnetZones[sub] == nil {
				subnetZones[sub] = map[string]bool{}
			}
			if webTierPorts[port] {
				subnetZones[sub]["web"] = true
			}
			if rule, ok := lateralHighRiskPorts[port]; ok {
				subnetZones[sub][rule.zone] = true
			}
		}
		if port > 0 {
			if hostPorts[host] == nil {
				hostPorts[host] = map[int]bool{}
			}
			hostPorts[host][port] = true
		}
	}

	for _, a := range assets {
		if strings.TrimSpace(a.CSegment) != "" {
			subnetSet[strings.TrimSpace(a.CSegment)] = true
		}
		host := strings.TrimSpace(a.IP)
		if host == "" {
			host = strings.TrimSpace(a.Domain)
		}
		if a.Port != nil && *a.Port > 0 {
			recordHostPort(host, *a.Port)
		} else if host != "" {
			recordHostPort(host, 0)
		}
		for _, p := range a.OpenPorts {
			switch v := p["port"].(type) {
			case float64:
				if int(v) > 0 {
					recordHostPort(host, int(v))
				}
			case int:
				if v > 0 {
					recordHostPort(host, v)
				}
			}
		}
	}

	var subnets []string
	for s := range subnetSet {
		subnets = append(subnets, s)
	}
	sort.Strings(subnets)

	var risks []LateralSegmentationRisk
	exposedHighRisk := 0
	zoneViolations := 0

	// 1. Multi-subnet flat reachability risk.
	if len(subnets) >= 2 {
		zoneViolations++
		risks = append(risks, LateralSegmentationRisk{
			Category:    "multi_subnet_exposure",
			Severity:    "high",
			CheckCode:   "NET-BOUNDARY",
			Target:      strings.Join(subnets, ", "),
			Detail:      fmt.Sprintf("%d distinct /24 network segments are reachable within the same assessment boundary without enforced lateral isolation.", len(subnets)),
			Remediation: "Implement inter-VLAN firewall ACLs (default-deny) between business, management, and data subnets per MLPS 2.0 安全区域边界.",
		})
	}

	// 2. High-risk lateral management / data-plane / control-plane port exposure & co-location.
	var hosts []string
	for h := range hostPorts {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)

	for _, h := range hosts {
		ports := hostPorts[h]
		hasWeb := false
		var dataOrControl []string
		var portList []int
		for p := range ports {
			portList = append(portList, p)
			if webTierPorts[p] {
				hasWeb = true
			}
		}
		sort.Ints(portList)
		for _, p := range portList {
			rule, ok := lateralHighRiskPorts[p]
			if !ok {
				continue
			}
			exposedHighRisk++
			if rule.zone == "data" || rule.zone == "control" {
				dataOrControl = append(dataOrControl, fmt.Sprintf("%s(%d)", rule.service, p))
			}
			risks = append(risks, LateralSegmentationRisk{
				Category:    "lateral_service_exposure",
				Severity:    rule.severity,
				CheckCode:   rule.checkCode,
				Target:      fmt.Sprintf("%s:%d", h, p),
				Detail:      fmt.Sprintf("High-risk lateral-surface service %s (port %d, zone=%s) is exposed in recorded inventory.", rule.service, p, rule.zone),
				Remediation: rule.remediation,
			})
		}
		if hasWeb && len(dataOrControl) > 0 {
			zoneViolations++
			risks = append(risks, LateralSegmentationRisk{
				Category:    "web_data_tier_colocation",
				Severity:    "high",
				CheckCode:   "NET-BOUNDARY",
				Target:      h,
				Detail:      fmt.Sprintf("Host %s exposes both web/edge tier ports and internal data/control-plane services (%s) without tier separation.", h, strings.Join(dataOrControl, ", ")),
				Remediation: "Separate web/DMZ services from database/cache/control-plane tiers into distinct security zones with least-privilege egress/ingress policies.",
			})
		}
	}

	// 3. Same-subnet mixed web + data/control exposure.
	for _, sub := range subnets {
		z := subnetZones[sub]
		if z["web"] && (z["data"] || z["control"]) {
			zoneViolations++
			risks = append(risks, LateralSegmentationRisk{
				Category:    "flat_zone_mixing",
				Severity:    "high",
				CheckCode:   "NET-BOUNDARY",
				Target:      sub,
				Detail:      fmt.Sprintf("Subnet %s mixes web-facing hosts with database/control-plane services in the same L2/L3 broadcast domain.", sub),
				Remediation: "Partition DMZ/web hosts and internal data/control-plane hosts into separate VLANs/subnets with stateful boundary filtering.",
			})
		}
	}

	verdict := db.CheckStatusPassed
	if len(risks) > 0 {
		verdict = db.CheckStatusFailed
	}
	summary := fmt.Sprintf("Passive MLPS 2.0 lateral segmentation audit: %d assets, %d subnets, %d high-risk lateral ports, %d zone isolation violations (verdict=%s).",
		len(assets), len(subnets), exposedHighRisk, zoneViolations, verdict)

	if subnets == nil {
		subnets = []string{}
	}
	if risks == nil {
		risks = []LateralSegmentationRisk{}
	}
	return LateralSegmentationReport{
		TaskID:            taskID,
		TotalAssets:       len(assets),
		DistinctSubnets24: subnets,
		ExposedHighRisk:   exposedHighRisk,
		ZoneViolations:    zoneViolations,
		Verdict:           verdict,
		Risks:             risks,
		Summary:           summary,
	}
}

func (s *Server) toolAuditLateralSegmentation() actool.CoreTool {
	return wrTool(
		"audit_lateral_segmentation",
		"Passive MLPS 2.0 lateral-defense & network-segmentation compliance auditor (ZERO active scanning or exploitation): analyzes recorded task asset inventory to detect flat multi-subnet exposure, high-risk lateral management/data/control-plane ports (SMB/RDP/SSH/Redis/Docker/K8s/DB/LDAP), and DMZ-to-data tier isolation violations. Optionally records evidence directly into MLPS 2.0 task_checks (NET-BOUNDARY).",
		objSchema(map[string]any{
			"task_id":           strParam("Task ID (numeric string)"),
			"auto_record_check": map[string]any{"type": "boolean", "description": "If true, upsert NET-BOUNDARY compliance check result into task_checks automatically"},
		}, "task_id"),
		func(_ context.Context, raw json.RawMessage) (actool.Result, error) {
			var p struct {
				TaskID          string `json:"task_id"`
				AutoRecordCheck bool   `json:"auto_record_check"`
			}
			if err := json.Unmarshal(raw, &p); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			tid, err := strconv.ParseInt(strings.TrimSpace(p.TaskID), 10, 64)
			if err != nil || tid <= 0 {
				return actool.Errorf(fmt.Sprintf("invalid task_id %q", p.TaskID)), nil
			}
			var assets []*db.Asset
			if s.m != nil && s.m.assets != nil {
				assets, err = s.m.assets.QueryByTask(tid, "", 500, 0)
				if err != nil {
					return actool.Errorf(fmt.Sprintf("query task assets: %v", err)), nil
				}
			}
			rep := EvaluateLateralSegmentation(p.TaskID, assets)
			if p.AutoRecordCheck && s.m != nil && s.m.pg != nil {
				_, _ = s.m.pg.UpsertTaskCheckResult(tid, db.TaskCheckInput{
					CheckCode: "NET-BOUNDARY",
					Status:    rep.Verdict,
					Evidence:  rep.Summary,
					Notes:     fmt.Sprintf("subnets=%s, high_risk_ports=%d, zone_violations=%d", strings.Join(rep.DistinctSubnets24, ","), rep.ExposedHighRisk, rep.ZoneViolations),
					TestedBy:  "audit_lateral_segmentation",
				})
			}
			return jsonResult(rep)
		},
	)
}

// TrafficComplianceFinding describes one passive MLPS 2.0 configuration or data-leakage issue
// observed strictly in already-captured HTTP exchanges (zero active requests sent).
type TrafficComplianceFinding struct {
	Category    string `json:"category"`
	Severity    string `json:"severity"`
	CheckCode   string `json:"check_code"`
	ExchangeID  string `json:"exchange_id,omitempty"`
	URL         string `json:"url"`
	Detail      string `json:"detail"`
	Snippet     string `json:"snippet,omitempty"` // sensitive tokens are always masked
	Remediation string `json:"remediation"`
}

// TrafficComplianceSample is a minimal captured HTTP exchange input for passive compliance inspection.
type TrafficComplianceSample struct {
	ID       string
	URL      string
	Status   int
	RespHead string
	RespBody string
}

var (
	reAliyunAK     = regexp.MustCompile(`\bLTAI[0-9A-Za-z]{12,24}\b`)
	reAWSKey       = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)
	reTencentAK    = regexp.MustCompile(`\bAKID[0-9A-Za-z]{20,36}\b`)
	rePrivateKey   = regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----`)
	reConnString   = regexp.MustCompile(`(?i)\b(?:jdbc:(?:mysql|postgresql|oracle|sqlserver)|redis|mongodb|amqp)://[^\s"'<>]{8,160}`)
	reJWTToken     = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*`)
	reSensitiveURL = regexp.MustCompile(`(?i)(?:/actuator(?:/env|/heapdump|/mappings|/beans)?|/swagger(?:-ui)?|/v[23]/api-docs|/druid/|/metrics|/\.env|/\.git/config)`)
	reStackTrace   = regexp.MustCompile(`(?i)(?:java\.lang\.[A-Za-z]+Exception|org\.springframework\.|Traceback \(most recent call last\):|SQLSTATE\[[0-9A-Z]+\])`)
)

func maskSecretToken(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= 8 {
		return "***"
	}
	return s[:4] + "****" + s[len(s)-4:]
}

// InspectCapturedTrafficCompliance runs purely passive MLPS 2.0 compliance checks over
// already-captured HTTP response headers and bodies (never sends network traffic, masks secrets).
func InspectCapturedTrafficCompliance(samples []TrafficComplianceSample) []TrafficComplianceFinding {
	var out []TrafficComplianceFinding
	seen := map[string]bool{}
	add := func(f TrafficComplianceFinding) {
		key := f.Category + "|" + f.URL + "|" + f.Detail
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, f)
	}

	for _, s := range samples {
		head := textclean.CleanText(s.RespHead)
		body := textclean.CleanText(s.RespBody)
		lowerHead := strings.ToLower(head)

		// 1. Overly permissive CORS with credentials.
		if strings.Contains(lowerHead, "access-control-allow-origin: *") &&
			strings.Contains(lowerHead, "access-control-allow-credentials: true") {
			add(TrafficComplianceFinding{
				Category:    "cors_wildcard_credentials",
				Severity:    "high",
				CheckCode:   "WEB-XSS-CSRF",
				ExchangeID:  s.ID,
				URL:         s.URL,
				Detail:      "Response sets Access-Control-Allow-Origin: * alongside Access-Control-Allow-Credentials: true.",
				Remediation: "Restrict Access-Control-Allow-Origin to an explicit allowlist of trusted origins.",
			})
		}

		// 2. Session cookie security flags (HttpOnly / Secure / SameSite).
		for _, line := range strings.Split(head, "\n") {
			trimmed := strings.TrimSpace(line)
			if !strings.HasPrefix(strings.ToLower(trimmed), "set-cookie:") {
				continue
			}
			val := strings.TrimSpace(trimmed[len("set-cookie:"):])
			lv := strings.ToLower(val)
			cookieName := val
			if eq := strings.IndexByte(cookieName, '='); eq > 0 {
				cookieName = strings.TrimSpace(cookieName[:eq])
			}
			var missing []string
			if !strings.Contains(lv, "httponly") {
				missing = append(missing, "HttpOnly")
			}
			if strings.HasPrefix(strings.ToLower(s.URL), "https://") && !strings.Contains(lv, "secure") {
				missing = append(missing, "Secure")
			}
			if !strings.Contains(lv, "samesite") {
				missing = append(missing, "SameSite")
			}
			if len(missing) > 0 {
				add(TrafficComplianceFinding{
					Category:    "insecure_cookie_flags",
					Severity:    "medium",
					CheckCode:   "AUTH-SESSION",
					ExchangeID:  s.ID,
					URL:         s.URL,
					Detail:      fmt.Sprintf("Set-Cookie %q is missing security attribute(s): %s.", cookieName, strings.Join(missing, ", ")),
					Remediation: "Set HttpOnly, Secure (over HTTPS), and SameSite=Lax/Strict on session cookies.",
				})
			}
		}

		// 3. Missing HSTS on HTTPS responses.
		if strings.HasPrefix(strings.ToLower(s.URL), "https://") && s.Status >= 200 && s.Status < 400 &&
			!strings.Contains(lowerHead, "strict-transport-security:") {
			add(TrafficComplianceFinding{
				Category:    "missing_hsts",
				Severity:    "low",
				CheckCode:   "NET-TLS",
				ExchangeID:  s.ID,
				URL:         s.URL,
				Detail:      "HTTPS response omits Strict-Transport-Security (HSTS) header.",
				Remediation: "Enable Strict-Transport-Security: max-age=31536000; includeSubDomains on HTTPS endpoints.",
			})
		}

		// 4. Exposed debug / management endpoints observed returning 200 OK.
		if s.Status == 200 && reSensitiveURL.MatchString(s.URL) {
			add(TrafficComplianceFinding{
				Category:    "exposed_management_or_doc_endpoint",
				Severity:    "high",
				CheckCode:   "APP-API",
				ExchangeID:  s.ID,
				URL:         s.URL,
				Detail:      "Sensitive management, API documentation, or environment endpoint returned HTTP 200.",
				Remediation: "Disable debug/documentation endpoints in production or restrict them to authenticated internal management networks.",
			})
		}

		// 5. Passive secret / credential / private-key leakage in HTTP response body (always masked).
		for _, spec := range []struct {
			cat string
			re  *regexp.Regexp
			sev string
			msg string
		}{
			{"cloud_access_key_leak", reAliyunAK, "critical", "Potential Alibaba Cloud AccessKey ID exposed in HTTP response."},
			{"cloud_access_key_leak", reAWSKey, "critical", "Potential AWS AccessKey ID exposed in HTTP response."},
			{"cloud_access_key_leak", reTencentAK, "critical", "Potential Tencent Cloud SecretId exposed in HTTP response."},
			{"private_key_leak", rePrivateKey, "critical", "PEM private key material detected in HTTP response."},
			{"connection_string_leak", reConnString, "high", "Database or middleware connection URI exposed in HTTP response."},
		} {
			if m := spec.re.FindString(body); m != "" {
				add(TrafficComplianceFinding{
					Category:    spec.cat,
					Severity:    spec.sev,
					CheckCode:   "APP-API",
					ExchangeID:  s.ID,
					URL:         s.URL,
					Detail:      spec.msg,
					Snippet:     maskSecretToken(m),
					Remediation: "Rotate exposed credentials immediately and remove secret material from client-facing responses and bundles.",
				})
			}
		}

		// 6. Passive JWT structural audit (no secret cracking or token forging).
		if tok := reJWTToken.FindString(body); tok != "" {
			parts := strings.Split(tok, ".")
			if len(parts) == 3 {
				if hdrRaw, err := base64.RawURLEncoding.DecodeString(parts[0]); err == nil {
					var hdr map[string]any
					if json.Unmarshal(hdrRaw, &hdr) == nil {
						if alg, _ := hdr["alg"].(string); strings.EqualFold(alg, "none") || alg == "" {
							add(TrafficComplianceFinding{
								Category:    "jwt_insecure_alg",
								Severity:    "critical",
								CheckCode:   "AUTH-SESSION",
								ExchangeID:  s.ID,
								URL:         s.URL,
								Detail:      fmt.Sprintf("Observed JWT uses insecure algorithm header alg=%q.", alg),
								Snippet:     maskSecretToken(tok),
								Remediation: "Reject alg=none and pin an explicit strong signing algorithm (e.g. RS256/ES256 or strong HS256 secret) server-side.",
							})
						}
					}
				}
				if payRaw, err := base64.RawURLEncoding.DecodeString(parts[1]); err == nil {
					var claims map[string]any
					if json.Unmarshal(payRaw, &claims) == nil {
						if _, hasExp := claims["exp"]; !hasExp {
							add(TrafficComplianceFinding{
								Category:    "jwt_missing_exp",
								Severity:    "medium",
								CheckCode:   "AUTH-SESSION",
								ExchangeID:  s.ID,
								URL:         s.URL,
								Detail:      "Observed JWT payload lacks an expiration (exp) claim.",
								Snippet:     maskSecretToken(tok),
								Remediation: "Enforce short-lived exp claims and server-side token revocation on logout.",
							})
						}
					}
				}
			}
		}

		// 7. Verbose stack trace / SQL error disclosure.
		if m := reStackTrace.FindString(body); m != "" {
			add(TrafficComplianceFinding{
				Category:    "verbose_error_disclosure",
				Severity:    "low",
				CheckCode:   "APP-API",
				ExchangeID:  s.ID,
				URL:         s.URL,
				Detail:      "Response exposes internal framework stack trace or database error details.",
				Snippet:     m,
				Remediation: "Return generic error responses to clients and log detailed diagnostics server-side only.",
			})
		}
	}

	if out == nil {
		out = []TrafficComplianceFinding{}
	}
	return out
}

func (s *Server) toolAuditTrafficCompliance() actool.CoreTool {
	return roTool(
		"audit_traffic_compliance",
		"Passive MLPS 2.0 HTTP traffic & configuration compliance auditor (ZERO active requests): inspects already-captured exchanges in the local recording proxy for secret/AK/connection-string leaks (masked), insecure Set-Cookie attributes, CORS wildcard+credentials, missing HSTS, exposed debug/management endpoints, verbose stack traces, and passive JWT structural issues (missing exp / alg=none).",
		objSchema(map[string]any{
			"host":  strParam("Optional host filter to narrow captured traffic inspection"),
			"limit": map[string]any{"type": "integer", "description": "Maximum recent exchanges to inspect (default 60, max 200)"},
		}),
		func(_ context.Context, raw json.RawMessage) (actool.Result, error) {
			var p struct {
				Host  string `json:"host"`
				Limit int    `json:"limit"`
			}
			if err := json.Unmarshal(raw, &p); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if p.Limit <= 0 {
				p.Limit = 60
			}
			if p.Limit > 200 {
				p.Limit = 200
			}
			if s.m == nil || s.m.traffic == nil {
				return jsonResult(map[string]any{
					"inspected_exchanges": 0,
					"finding_count":       0,
					"findings":            []TrafficComplianceFinding{},
					"note":                "traffic recorder unavailable",
				})
			}
			rows, err := s.m.traffic.Search(strings.TrimSpace(p.Host), 0, p.Limit)
			if err != nil {
				return actool.Errorf(fmt.Sprintf("query traffic: %v", err)), nil
			}
			samples := make([]TrafficComplianceSample, 0, len(rows))
			for _, row := range rows {
				_, rawResp, gerr := s.m.traffic.Get(row.ID)
				if gerr != nil || rawResp == "" {
					continue
				}
				respHead, respBody := rawResp, ""
				if idx := strings.Index(rawResp, "\n\n"); idx >= 0 {
					respHead = rawResp[:idx]
					respBody = rawResp[idx+2:]
				}
				samples = append(samples, TrafficComplianceSample{
					ID:       row.ID,
					URL:      row.URL,
					Status:   row.Status,
					RespHead: respHead,
					RespBody: respBody,
				})
			}
			findings := InspectCapturedTrafficCompliance(samples)
			return jsonResult(map[string]any{
				"host":                strings.TrimSpace(p.Host),
				"inspected_exchanges": len(samples),
				"finding_count":       len(findings),
				"findings":            findings,
			})
		},
	)
}
