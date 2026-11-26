package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/textclean"
	actool "github.com/Autumn-27/norma/tool"
)

// ExpandedSurfaceEndpoint describes one endpoint discovered passively from captured traffic,
// HTML forms, JS bundles, robots/sitemap, or redirect/CORS headers.
type ExpandedSurfaceEndpoint struct {
	Method string           `json:"method"`
	URL    string           `json:"url"`
	Source string           `json:"source"` // traffic_request | html_form | js_route | robots_sitemap | redirect_header | graphql
	Params []map[string]any `json:"params,omitempty"`
	Tags   []string         `json:"tags,omitempty"`
}

// ExpandedIntranetNode describes an internal IP/hostname/service reference passively discovered
// in captured HTTP headers, configs, error pages, or JS bundles (zero active network probing).
type ExpandedIntranetNode struct {
	Host    string `json:"host"`
	Port    int    `json:"port,omitempty"`
	Subnet  string `json:"subnet,omitempty"` // /24 C-segment for IPv4
	Scheme  string `json:"scheme,omitempty"` // http | https | ws | wss | redis | mysql | postgres | etc.
	Source  string `json:"source"`           // header_leak | body_ip_ref | internal_domain | service_uri
	Context string `json:"context,omitempty"`
}

// SurfaceExpansionReport summarizes newly discovered hosts, endpoints, internal surface nodes,
// and parameter surfaces extracted passively from already-captured traffic (zero active network requests).
type SurfaceExpansionReport struct {
	TaskID                   string                    `json:"task_id"`
	InspectedExchanges       int                       `json:"inspected_exchanges"`
	DiscoveredHosts          []string                  `json:"discovered_hosts"`
	DiscoveredInternalNodes  []ExpandedIntranetNode    `json:"discovered_internal_nodes"`
	DiscoveredInternalSubnets []string                 `json:"discovered_internal_subnets"`
	DiscoveredEndpoints      []ExpandedSurfaceEndpoint `json:"discovered_endpoints"`
	RegisteredEndpoints      int                       `json:"registered_endpoints"`
	RegisteredInternalIPs    int                       `json:"registered_internal_ips"`
	FenceFilteredOut         int                       `json:"fence_filtered_out"`
}

var (
	reFormTag       = regexp.MustCompile(`(?is)<form\b([^>]*)>(.*?)</form>`)
	reAttrAction    = regexp.MustCompile(`(?i)\baction\s*=\s*["']([^"']+)["']`)
	reAttrMethod    = regexp.MustCompile(`(?i)\bmethod\s*=\s*["']([^"']+)["']`)
	reInputName     = regexp.MustCompile(`(?i)<(?:input|select|textarea)\b[^>]*\bname\s*=\s*["']([A-Za-z0-9_.\-\[\]]+)["']`)
	reJSFetchCall   = regexp.MustCompile(`(?i)\b(?:fetch|axios\.(?:get|post|put|delete|patch)|open)\s*\(\s*["']((?:/|https?://)[^"'\s?#]{2,180})`)
	reRobotsPath    = regexp.MustCompile(`(?im)^(?:Disallow|Allow)\s*:\s*(/[^\s#]+)`)
	reSitemapLoc    = regexp.MustCompile(`(?i)<loc>\s*(https?://[^<\s]+)\s*</loc>`)
	reGraphQLOp     = regexp.MustCompile(`(?i)\b(?:query|mutation)\s+([A-Za-z_][A-Za-z0-9_]{1,60})\s*(?:\(|\{)`)
	reURLHostInText = regexp.MustCompile(`https?://([a-zA-Z0-9.-]+(?::\d{1,5})?)`)
	reRFC1918Host   = regexp.MustCompile(`\b((?:10\.(?:\d{1,3}\.){2}\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}))(?::(\d{1,5}))?\b`)
	reInternalDom   = regexp.MustCompile(`(?i)\b([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\.(?:local|internal|corp|lan|intranet|svc\.cluster\.local|home\.arpa))(?::(\d{1,5}))?\b`)
	reServiceURI    = regexp.MustCompile(`(?i)\b(wss?|redis|mysql|postgres(?:ql)?|mongodb|amqp|ldap|ldaps)://(?:[^@\s"'<>]+@)?([a-zA-Z0-9.-]+)(?::(\d{1,5}))?`)
)

func resolveRelativeURL(baseRaw, ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" || strings.HasPrefix(ref, "javascript:") || strings.HasPrefix(ref, "mailto:") || strings.HasPrefix(ref, "#") {
		return ""
	}
	base, err := url.Parse(strings.TrimSpace(baseRaw))
	if err != nil || base.Scheme == "" || base.Host == "" {
		return ""
	}
	u, err := base.Parse(ref)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return ""
	}
	u.Fragment = ""
	return u.String()
}

// ExtractSurfaceFromSamples passively expands the asset & endpoint inventory from already-captured
// HTTP exchanges (HTML forms, JS API calls, robots.txt/sitemap.xml, GraphQL ops, redirect/CSP hosts).
// Optional allowURL filter enforces the task's electronic fence so out-of-scope hosts are excluded.
func ExtractSurfaceFromSamples(
	taskID string,
	samples []TrafficComplianceSample,
	allowURL func(string) bool,
) SurfaceExpansionReport {
	hostSet := map[string]bool{}
	epMap := map[string]ExpandedSurfaceEndpoint{}
	internalNodeMap := map[string]ExpandedIntranetNode{}
	internalSubnetSet := map[string]bool{}
	filteredOut := 0

	addInternalNode := func(host string, port int, scheme, source, ctxHint string) {
		host = strings.ToLower(strings.TrimSpace(host))
		if host == "" {
			return
		}
		if port < 0 || port > 65535 {
			port = 0
		}
		checkURL := "http://" + host + "/"
		if port > 0 {
			checkURL = fmt.Sprintf("http://%s:%d/", host, port)
		}
		if allowURL != nil && !allowURL(checkURL) {
			filteredOut++
			return
		}
		subnet := ""
		if ip, err := netip.ParseAddr(host); err == nil {
			if !ip.Is4() {
				return
			}
			b := ip.As4()
			subnet = fmt.Sprintf("%d.%d.%d.0/24", b[0], b[1], b[2])
			internalSubnetSet[subnet] = true
		}
		key := fmt.Sprintf("%s:%d:%s", host, port, scheme)
		if _, exists := internalNodeMap[key]; !exists {
			internalNodeMap[key] = ExpandedIntranetNode{
				Host:    host,
				Port:    port,
				Subnet:  subnet,
				Scheme:  scheme,
				Source:  source,
				Context: ctxHint,
			}
		}
		hostSet[host] = true
	}

	addHost := func(host string) {
		host = strings.ToLower(strings.TrimSpace(host))
		if host == "" {
			return
		}
		if allowURL != nil && !allowURL("http://"+host+"/") {
			filteredOut++
			return
		}
		hostSet[host] = true
	}

	addEndpoint := func(method, rawURL, source string, params []map[string]any) {
		rawURL = strings.TrimSpace(rawURL)
		if rawURL == "" {
			return
		}
		u, err := url.Parse(rawURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return
		}
		if allowURL != nil && !allowURL(rawURL) {
			filteredOut++
			return
		}
		hostSet[strings.ToLower(u.Host)] = true

		// Extract query parameters into params slice and normalize URL without query noise.
		seenParam := map[string]bool{}
		var mergedParams []map[string]any
		for _, p := range params {
			if n, _ := p["name"].(string); n != "" && !seenParam[n] {
				seenParam[n] = true
				mergedParams = append(mergedParams, p)
			}
		}
		for k := range u.Query() {
			if k != "" && !seenParam[k] {
				seenParam[k] = true
				mergedParams = append(mergedParams, map[string]any{"name": k, "location": "query"})
			}
		}
		u.RawQuery = ""
		u.Fragment = ""
		normURL := u.String()

		m := strings.ToUpper(strings.TrimSpace(method))
		if m == "" {
			m = "GET"
		}
		key := m + " " + normURL
		if existing, exists := epMap[key]; exists {
			// Merge newly observed parameter names.
			exSeen := map[string]bool{}
			for _, ep := range existing.Params {
				if n, _ := ep["name"].(string); n != "" {
					exSeen[n] = true
				}
			}
			for _, np := range mergedParams {
				if n, _ := np["name"].(string); n != "" && !exSeen[n] {
					exSeen[n] = true
					existing.Params = append(existing.Params, np)
				}
			}
			existing.Tags = ClassifyEndpointParamTags(existing.Params, normURL)
			epMap[key] = existing
			return
		}
		epMap[key] = ExpandedSurfaceEndpoint{
			Method: m,
			URL:    normURL,
			Source: source,
			Params: mergedParams,
			Tags:   ClassifyEndpointParamTags(mergedParams, normURL),
		}
	}

	for _, s := range samples {
		head := textclean.CleanText(s.RespHead)
		body := textclean.CleanText(s.RespBody)

		// 1. Register the observed exchange URL itself.
		if s.URL != "" {
			addEndpoint("GET", s.URL, "traffic_request", nil)
		}

		// 2. Inspect redirect Location and CSP headers for additional in-scope hosts/routes.
		for _, line := range strings.Split(head, "\n") {
			trimmed := strings.TrimSpace(line)
			low := strings.ToLower(trimmed)
			if strings.HasPrefix(low, "location:") {
				loc := strings.TrimSpace(trimmed[len("location:"):])
				if resolved := resolveRelativeURL(s.URL, loc); resolved != "" {
					addEndpoint("GET", resolved, "redirect_header", nil)
				}
			} else if strings.HasPrefix(low, "content-security-policy:") {
				for _, m := range reURLHostInText.FindAllStringSubmatch(trimmed, 20) {
					addHost(m[1])
				}
			}
		}

		if body == "" {
			continue
		}

		// 3. HTML <form> actions and input parameter names.
		for _, fm := range reFormTag.FindAllStringSubmatch(body, 30) {
			attrs, inner := fm[1], fm[2]
			action := s.URL
			if am := reAttrAction.FindStringSubmatch(attrs); len(am) >= 2 {
				if resolved := resolveRelativeURL(s.URL, am[1]); resolved != "" {
					action = resolved
				}
			}
			method := "POST"
			if mm := reAttrMethod.FindStringSubmatch(attrs); len(mm) >= 2 {
				method = strings.ToUpper(strings.TrimSpace(mm[1]))
			}
			var formParams []map[string]any
			for _, im := range reInputName.FindAllStringSubmatch(inner, 30) {
				formParams = append(formParams, map[string]any{"name": im[1], "location": "body"})
			}
			addEndpoint(method, action, "html_form", formParams)
		}

		// 4. JS API calls (fetch / axios / XHR) & contract routes.
		for _, jm := range reJSFetchCall.FindAllStringSubmatch(body, 60) {
			if resolved := resolveRelativeURL(s.URL, jm[1]); resolved != "" {
				addEndpoint("GET", resolved, "js_route", nil)
			}
		}
		if baseURL := originOfURL(s.URL); baseURL != "" {
			for _, ep := range ParseJSBundleEndpoints(baseURL, "js_route", body) {
				addEndpoint(ep.Method, ep.URL, "js_route", ep.Params)
			}
		}

		// 5. robots.txt and sitemap.xml routes.
		lowURL := strings.ToLower(s.URL)
		if strings.HasSuffix(lowURL, "/robots.txt") || strings.Contains(body, "Disallow:") {
			for _, rm := range reRobotsPath.FindAllStringSubmatch(body, 60) {
				p := strings.TrimRight(rm[1], "*")
				if resolved := resolveRelativeURL(s.URL, p); resolved != "" {
					addEndpoint("GET", resolved, "robots_sitemap", nil)
				}
			}
		}
		if strings.Contains(body, "<loc>") {
			for _, sm := range reSitemapLoc.FindAllStringSubmatch(body, 80) {
				addEndpoint("GET", sm[1], "robots_sitemap", nil)
			}
		}

		// 6. GraphQL operation names observed in JS/API responses.
		for _, gm := range reGraphQLOp.FindAllStringSubmatch(body, 30) {
			if baseURL := originOfURL(s.URL); baseURL != "" {
				addEndpoint("POST", baseURL+"/graphql", "graphql", []map[string]any{
					{"name": gm[1], "location": "graphql_op"},
				})
			}
		}

		// 7. Passive intranet surface mapping: extract RFC1918 IPs, internal corporate domains
		// (.local/.internal/.corp/.svc.cluster.local), and internal middleware/WebSocket URIs
		// from captured headers and bodies (credentials in URIs are never captured).
		for _, m := range reRFC1918Host.FindAllStringSubmatch(s.URL+"\n"+head, 20) {
			port, _ := strconv.Atoi(m[2])
			addInternalNode(m[1], port, "", "header_leak", s.URL)
		}
		for _, m := range reRFC1918Host.FindAllStringSubmatch(body, 40) {
			port, _ := strconv.Atoi(m[2])
			addInternalNode(m[1], port, "", "body_ip_ref", s.URL)
		}
		for _, m := range reInternalDom.FindAllStringSubmatch(head+"\n"+body, 40) {
			port, _ := strconv.Atoi(m[2])
			addInternalNode(m[1], port, "", "internal_domain", s.URL)
		}
		for _, m := range reServiceURI.FindAllStringSubmatch(body, 30) {
			port, _ := strconv.Atoi(m[3])
			addInternalNode(m[2], port, strings.ToLower(m[1]), "service_uri", s.URL)
		}
	}

	hosts := make([]string, 0, len(hostSet))
	for h := range hostSet {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)

	internalSubnets := make([]string, 0, len(internalSubnetSet))
	for sub := range internalSubnetSet {
		internalSubnets = append(internalSubnets, sub)
	}
	sort.Strings(internalSubnets)

	internalNodes := make([]ExpandedIntranetNode, 0, len(internalNodeMap))
	for _, n := range internalNodeMap {
		internalNodes = append(internalNodes, n)
	}
	sort.Slice(internalNodes, func(i, j int) bool {
		if internalNodes[i].Host != internalNodes[j].Host {
			return internalNodes[i].Host < internalNodes[j].Host
		}
		return internalNodes[i].Port < internalNodes[j].Port
	})

	eps := make([]ExpandedSurfaceEndpoint, 0, len(epMap))
	for _, ep := range epMap {
		eps = append(eps, ep)
	}
	sort.Slice(eps, func(i, j int) bool {
		if eps[i].URL != eps[j].URL {
			return eps[i].URL < eps[j].URL
		}
		return eps[i].Method < eps[j].Method
	})

	return SurfaceExpansionReport{
		TaskID:                    taskID,
		InspectedExchanges:        len(samples),
		DiscoveredHosts:           hosts,
		DiscoveredInternalNodes:   internalNodes,
		DiscoveredInternalSubnets: internalSubnets,
		DiscoveredEndpoints:       eps,
		FenceFilteredOut:          filteredOut,
	}
}

func originOfURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

func (s *Server) toolExpandSurfaceFromTraffic() actool.CoreTool {
	return wrTool(
		"expand_surface_from_traffic",
		"Passive attack-surface expansion engine (ZERO active requests): mines already-captured HTTP traffic in the local recording proxy to extract hidden/sibling hosts (Location/CSP), HTML forms & input fields, JS fetch/axios/XHR routes, robots.txt/sitemap.xml paths, and GraphQL operations. Filters strictly through the task electronic fence and optionally registers newly discovered endpoints into the task asset graph.",
		objSchema(map[string]any{
			"task_id":         strParam("Task ID (numeric string)"),
			"host":            strParam("Optional host filter to narrow captured traffic"),
			"limit":           map[string]any{"type": "integer", "description": "Max recent exchanges to mine (default 80, max 200)"},
			"register_assets": map[string]any{"type": "boolean", "description": "Register discovered endpoints into the task asset graph (default true)"},
		}, "task_id"),
		func(_ context.Context, raw json.RawMessage) (actool.Result, error) {
			var p struct {
				TaskID         string `json:"task_id"`
				Host           string `json:"host"`
				Limit          int    `json:"limit"`
				RegisterAssets *bool  `json:"register_assets"`
			}
			if err := json.Unmarshal(raw, &p); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			t := s.m.ResolveTask(strings.TrimSpace(p.TaskID))
			if t == nil {
				return actool.Errorf(fmt.Sprintf("task %q not found", p.TaskID)), nil
			}
			tid, _ := strconv.ParseInt(t.ID, 10, 64)
			if p.Limit <= 0 {
				p.Limit = 80
			}
			if p.Limit > 200 {
				p.Limit = 200
			}

			var samples []TrafficComplianceSample
			if s.m != nil && s.m.traffic != nil {
				rows, err := s.m.traffic.Search(strings.TrimSpace(p.Host), 0, p.Limit)
				if err != nil {
					return actool.Errorf(fmt.Sprintf("search traffic: %v", err)), nil
				}
				for _, row := range rows {
					_, rawResp, gerr := s.m.traffic.Get(row.ID)
					if gerr != nil {
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
			}

			var allowFn func(string) bool
			if t.FenceEnabled && t.Guard != nil {
				allowFn = func(u string) bool {
					probe, _ := json.Marshal(map[string]string{"url": u})
					blocked, _ := t.Guard.CheckFence("WebFetch", probe)
					return !blocked
				}
			}

			rep := ExtractSurfaceFromSamples(t.ID, samples, allowFn)

			register := p.RegisterAssets == nil || *p.RegisterAssets
			if register && s.m != nil && s.m.assets != nil && tid > 0 {
				for _, ep := range rep.DiscoveredEndpoints {
					if _, err := s.m.assets.UpsertEndpoint(db.UpsertEndpointReq{
						URL:    ep.URL,
						Method: ep.Method,
						Params: ep.Params,
						TaskID: tid,
					}); err == nil {
						rep.RegisteredEndpoints++
					}
				}
				seenIP := map[string]bool{}
				for _, node := range rep.DiscoveredInternalNodes {
					if node.Subnet != "" && !seenIP[node.Host] {
						seenIP[node.Host] = true
						var ports []db.PortService
						if node.Port > 0 {
							ports = append(ports, db.PortService{Port: node.Port, Service: node.Scheme})
						}
						if _, err := s.m.assets.UpsertIP(db.UpsertIPReq{
							IP:        node.Host,
							OpenPorts: ports,
							TaskID:    tid,
						}); err == nil {
							rep.RegisteredInternalIPs++
						}
					}
				}
			}
			return jsonResult(rep)
		},
	)
}
