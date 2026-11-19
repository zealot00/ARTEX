package server

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/guard"
)

func TestPocsAdminOnlyRoutes(t *testing.T) {
	s := &Server{jwtKey: []byte("0123456789abcdef0123456789abcdef")}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/pocs", s.listPocs)
	mux.HandleFunc("POST /api/pocs", s.createPoc)
	mux.HandleFunc("DELETE /api/pocs/{id}", s.deletePoc)
	h := s.requireAuth(mux)

	for _, tc := range []struct {
		method string
		path   string
	}{
		{"GET", "/api/pocs"},
		{"POST", "/api/pocs"},
		{"DELETE", "/api/pocs/1"},
	} {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != 401 {
			t.Fatalf("%s %s unauth: got %d, want 401", tc.method, tc.path, rec.Code)
		}
	}
}

func TestSearchPocsOfflineTemplatesAndFence(t *testing.T) {
	tmp := t.TempDir()
	tplDir := filepath.Join(tmp, "http", "cves", "2024")
	if err := os.MkdirAll(tplDir, 0o755); err != nil {
		t.Fatal(err)
	}
	tplFile := filepath.Join(tplDir, "CVE-2024-9999.yaml")
	if err := os.WriteFile(tplFile, []byte("id: CVE-2024-9999\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARTEX_NUCLEI_TEMPLATES_DIR", tmp)

	rules, err := guard.ParseFenceRules([]string{"10.10.0.0/16"})
	if err != nil {
		t.Fatal(err)
	}
	g := guard.New()
	g.SetFence(true, rules)
	task := &Task{ID: "99", FenceEnabled: true, Guard: g}
	m := &Manager{tasks: map[string]*Task{"99": task}}

	s := &Server{m: m}

	searchTool := s.toolSearchPocs()
	res, err := searchTool.Call(context.Background(), json.RawMessage(`{"query":"CVE-2024-9999"}`), nil)
	if err != nil || res.IsError {
		t.Fatalf("search_pocs failed: err=%v res=%+v", err, res)
	}
	if !strings.Contains(resultText(res), "http/cves/2024/CVE-2024-9999.yaml") {
		t.Fatalf("expected offline template in search_pocs output: %s", resultText(res))
	}

	runTool := s.toolRunPoc()
	// Out-of-scope target must be blocked by electronic fence before invoking nuclei.
	resBlocked, err := runTool.Call(context.Background(), json.RawMessage(`{"task_id":"99","target":"http://192.168.1.50:8080","template_path":"http/cves/2024/CVE-2024-9999.yaml"}`), nil)
	if err != nil {
		t.Fatalf("run_poc error: %v", err)
	}
	if !resBlocked.IsError || !strings.Contains(resultText(resBlocked), "electronic fence blocked") {
		t.Fatalf("expected electronic fence block, got: %+v", resBlocked)
	}

	// Flag/whitespace injection in target must be rejected before fence/exec.
	for _, badTarget := range []string{"-u http://10.10.1.5", "http://10.10.1.5 -o /tmp/out", "http://10.10.1.5\n--help"} {
		badPayload, _ := json.Marshal(map[string]any{
			"task_id":       "99",
			"target":        badTarget,
			"template_path": "http/cves/2024/CVE-2024-9999.yaml",
		})
		resBad, err := runTool.Call(context.Background(), badPayload, nil)
		if err != nil {
			t.Fatalf("run_poc bad target %q error: %v", badTarget, err)
		}
		if !resBad.IsError {
			t.Fatalf("expected invalid target rejection for %q, got: %+v", badTarget, resBad)
		}
	}

	// Path traversal in template_path must be rejected.
	resTrav, err := runTool.Call(context.Background(), json.RawMessage(`{"task_id":"99","target":"http://10.10.1.5:8080","template_path":"../../etc/passwd"}`), nil)
	if err != nil {
		t.Fatalf("run_poc traversal error: %v", err)
	}
	if !resTrav.IsError {
		t.Fatalf("expected path traversal rejection, got: %+v", resTrav)
	}

	// Inline custom python_script PoC execution under fence + OOB env injection.
	inlinePayload, _ := json.Marshal(map[string]any{
		"task_id":        "99",
		"target":         "http://10.10.1.5:8080",
		"inline_kind":    "python_script",
		"oob_token":      "tok123",
		"inline_content": "import os\nprint(os.environ.get('ARTEX_POC_TARGET'), os.environ.get('ARTEX_OOB_TOKEN'))\n",
	})
	resInline, err := runTool.Call(context.Background(), inlinePayload, nil)
	if err != nil || resInline.IsError {
		t.Fatalf("run_poc inline python_script failed: err=%v res=%+v", err, resInline)
	}
	txt := resultText(resInline)
	if !strings.Contains(txt, "http://10.10.1.5:8080 tok123") || !strings.Contains(txt, `"matched":true`) {
		t.Fatalf("unexpected inline PoC output: %s", txt)
	}
}

func TestDefaultInfraPocsCatalogAndRedisProbe(t *testing.T) {
	pocs := defaultIntranetPocs()
	if len(pocs) < 75 {
		t.Fatalf("expected at least 75 file-based intranet/infra PoCs in pocs/, got %d", len(pocs))
	}
	seen := map[string]bool{}
	var redisScript, memcachedScript, rsyncScript, printScript, zkScript, pgScript string
	for _, p := range pocs {
		if p.Name == "" || strings.TrimSpace(p.Content) == "" {
			t.Fatalf("invalid default poc entry: %+v", p)
		}
		if seen[p.Name] {
			t.Fatalf("duplicate default poc name: %s", p.Name)
		}
		seen[p.Name] = true
		if p.Kind != db.PocKindNucleiYAML && p.Kind != db.PocKindPythonScript {
			t.Fatalf("invalid kind %q on %s", p.Kind, p.Name)
		}
		switch p.Name {
		case "infra-redis-unauth-probe":
			redisScript = p.Content
		case "infra-memcached-unauth-stats":
			memcachedScript = p.Content
		case "infra-rsync-anonymous-modules":
			rsyncScript = p.Content
		case "infra-print-cups-ipp-exposure":
			printScript = p.Content
		case "infra-zookeeper-unauth-4lw":
			zkScript = p.Content
		case "infra-postgresql-trust-auth":
			pgScript = p.Content
		}
	}
	for _, required := range []string{
		"infra-samba-smb-null-signing",
		"infra-k8s-kubelet-unauth",
		"infra-k8s-etcd-unauth",
		"infra-k8s-dashboard-unauth",
		"infra-docker-registry-harbor-unauth",
		"infra-redis-unauth-probe",
		"infra-elasticsearch-unauth",
		"infra-jenkins-unauth-exposure",
		"infra-ldap-anonymous-bind",
		"infra-snmp-default-community",
		"infra-ssh-weak-algos-auth",
		"infra-ntp-monlist-info",
		"infra-print-cups-ipp-exposure",
		"infra-ftp-anonymous-login",
		"infra-memcached-unauth-stats",
		"infra-rsync-anonymous-modules",
		"infra-nfs-export-exposure",
		"infra-dns-zone-transfer-axfr",
		"infra-mongodb-unauth-probe",
		"infra-zookeeper-unauth-4lw",
		"infra-kafka-ui-akhq-exposure",
		"infra-hadoop-yarn-hdfs-unauth",
		"infra-spark-flink-unauth",
		"infra-rabbitmq-management-exposure",
		"infra-gitlab-public-explore",
		"infra-nexus-artifactory-unauth",
		"infra-sonarqube-unauth-exposure",
		"infra-kibana-unauth-exposure",
		"infra-xxljob-admin-exposure",
		"infra-eureka-consul-unauth",
		"infra-minio-console-metrics",
		"infra-nginx-apache-status-leak",
		"infra-tls-weak-protocol-cipher",
		"infra-postgresql-trust-auth",
		"infra-mysql-empty-root-probe",
		"infra-redis-sentinel-config-audit",
		"infra-clickhouse-unauth-http",
		"infra-couchdb-unauth-admin",
		"infra-influxdb-unauth-query",
		"infra-openstack-keystone-api",
		"infra-vmware-vcenter-esxi-exposure",
		"infra-portainer-rancher-exposure",
		"infra-hashicorp-vault-status",
		"infra-k8s-apiserver-anon-access",
		"infra-zabbix-unauth-exposure",
		"infra-tomcat-manager-exposure",
		"infra-weblogic-console-exposure",
		"infra-apollo-sentinel-unauth",
		"infra-apisix-admin-exposure",
		"infra-kong-admin-exposure",
		"infra-traefik-dashboard-unauth",
		"infra-activemq-console-exposure",
		"infra-rocketmq-console-unauth",
		"infra-jboss-wildfly-console",
		"infra-argocd-unauth-exposure",
		"infra-skywalking-pinpoint-unauth",
		"infra-neo4j-browser-unauth",
		"infra-phpmyadmin-adminer-exposure",
		"infra-presto-trino-unauth",
		"infra-nomad-unauth-api",
		"infra-openshift-console-api",
		"infra-ipmi-bmc-exposure",
		"infra-smtp-open-relay-vrfy",
	} {
		if !seen[required] {
			t.Fatalf("missing required infra PoC %q", required)
		}
	}

	// Execute the built-in Redis unauth probe against a local mock TCP listener.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 256)
		_, _ = conn.Read(buf)
		_, _ = conn.Write([]byte("+PONG\r\n# Server\r\nredis_version:7.2.4\r\nos:Linux\r\n"))
	}()

	task := &Task{ID: "101", Guard: guard.New()}
	s := &Server{m: &Manager{tasks: map[string]*Task{"101": task}}}
	runTool := s.toolRunPoc()
	payload, _ := json.Marshal(map[string]any{
		"task_id":        "101",
		"target":         ln.Addr().String(),
		"inline_kind":    "python_script",
		"inline_content": redisScript,
	})
	res, err := runTool.Call(context.Background(), payload, nil)
	if err != nil || res.IsError {
		t.Fatalf("redis probe failed: err=%v res=%+v", err, res)
	}
	txt := resultText(res)
	if !strings.Contains(txt, "CONFIRMED Redis unauthenticated access") || !strings.Contains(txt, "redis_version:7.2.4") {
		t.Fatalf("unexpected redis probe output: %s", txt)
	}

	// Execute Memcached unauth probe against a local mock TCP listener.
	mcLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer mcLn.Close()
	go func() {
		conn, err := mcLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 128)
		_, _ = conn.Read(buf)
		_, _ = conn.Write([]byte("STAT version 1.6.22\r\nSTAT curr_items 42\r\nEND\r\n"))
	}()
	mcPayload, _ := json.Marshal(map[string]any{
		"task_id":        "101",
		"target":         mcLn.Addr().String(),
		"inline_kind":    "python_script",
		"inline_content": memcachedScript,
	})
	mcRes, err := runTool.Call(context.Background(), mcPayload, nil)
	if err != nil || mcRes.IsError || !strings.Contains(resultText(mcRes), "CONFIRMED Memcached unauthenticated access") {
		t.Fatalf("memcached probe failed: err=%v res=%+v", err, mcRes)
	}

	// Execute rsync anonymous module listing probe against a local mock TCP listener.
	rsLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer rsLn.Close()
	go func() {
		conn, err := rsLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte("@RSYNCD: 31.0\n"))
		buf := make([]byte, 256)
		_, _ = conn.Read(buf)
		_, _ = conn.Write([]byte("backups\tDaily backups\n@RSYNCD: EXIT\n"))
	}()
	rsPayload, _ := json.Marshal(map[string]any{
		"task_id":        "101",
		"target":         rsLn.Addr().String(),
		"inline_kind":    "python_script",
		"inline_content": rsyncScript,
	})
	rsRes, err := runTool.Call(context.Background(), rsPayload, nil)
	if err != nil || rsRes.IsError || !strings.Contains(resultText(rsRes), "backups") {
		t.Fatalf("rsync probe failed: err=%v res=%+v", err, rsRes)
	}

	// Execute CUPS print exposure probe against a local mock HTTP server.
	cupsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "CUPS/2.4")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("<html><title>Printers - CUPS 2.4</title></html>"))
	}))
	defer cupsSrv.Close()
	cupsPayload, _ := json.Marshal(map[string]any{
		"task_id":        "101",
		"target":         cupsSrv.URL,
		"inline_kind":    "python_script",
		"inline_content": printScript,
	})
	cupsRes, err := runTool.Call(context.Background(), cupsPayload, nil)
	if err != nil || cupsRes.IsError || !strings.Contains(resultText(cupsRes), "CUPS_EXPOSED") {
		t.Fatalf("cups print probe failed: err=%v res=%+v", err, cupsRes)
	}

	// Execute ZooKeeper 4lw probe against a local mock TCP listener.
	zkLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer zkLn.Close()
	go func() {
		for i := 0; i < 3; i++ {
			conn, err := zkLn.Accept()
			if err != nil {
				return
			}
			buf := make([]byte, 32)
			_, _ = conn.Read(buf)
			_, _ = conn.Write([]byte("imok\n"))
			_ = conn.Close()
		}
	}()
	zkPayload, _ := json.Marshal(map[string]any{
		"task_id":        "101",
		"target":         zkLn.Addr().String(),
		"inline_kind":    "python_script",
		"inline_content": zkScript,
	})
	zkRes, err := runTool.Call(context.Background(), zkPayload, nil)
	if err != nil || zkRes.IsError || !strings.Contains(resultText(zkRes), "imok") {
		t.Fatalf("zookeeper probe failed: err=%v res=%+v", err, zkRes)
	}

	// Execute PostgreSQL trust auth probe against a local mock TCP listener returning AuthenticationOk ('R', len=8, auth=0).
	pgLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pgLn.Close()
	go func() {
		conn, err := pgLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 256)
		_, _ = conn.Read(buf)
		_, _ = conn.Write([]byte{'R', 0, 0, 0, 8, 0, 0, 0, 0})
	}()
	pgPayload, _ := json.Marshal(map[string]any{
		"task_id":        "101",
		"target":         pgLn.Addr().String(),
		"inline_kind":    "python_script",
		"inline_content": pgScript,
	})
	pgRes, err := runTool.Call(context.Background(), pgPayload, nil)
	if err != nil || pgRes.IsError || !strings.Contains(resultText(pgRes), "CONFIRMED PostgreSQL trust") {
		t.Fatalf("postgresql trust probe failed: err=%v res=%+v", err, pgRes)
	}
}
