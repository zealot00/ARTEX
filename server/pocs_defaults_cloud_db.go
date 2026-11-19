package server

import "github.com/Autumn-27/artex/db"

func cloudAndDBInfraPocs() []db.UpsertPocInput {
	return []db.UpsertPocInput{
		{
			Name:            "infra-postgresql-trust-auth",
			Kind:            db.PocKindPythonScript,
			Severity:        "critical",
			Tags:            "postgresql,postgres,database,unauth,infra,intranet",
			Description:     "Pure-TCP PostgreSQL wire-protocol startup probe checking whether :5432 accepts trust (passwordless) authentication for user 'postgres'.",
			ExploitGuidance: "Replace 'trust' with 'scram-sha-256' in pg_hba.conf and restrict listen_addresses.",
			CreatedBy:       "system",
			Content: `import os, socket, struct, sys, urllib.parse

raw = os.environ.get("ARTEX_POC_TARGET", "").strip()
if not raw:
    print("ARTEX_POC_TARGET is required", file=sys.stderr)
    sys.exit(2)

host, port = raw, 5432
if "://" in raw:
    u = urllib.parse.urlsplit(raw)
    host = u.hostname or raw
    port = u.port or 5432
elif ":" in raw:
    h, p = raw.rsplit(":", 1)
    host = h.strip("[]")
    try:
        port = int(p)
    except ValueError:
        port = 5432

# PostgreSQL v3.0 StartupMessage: length(4) + protocol(196608) + params + \x00
params = b"user\x00postgres\x00database\x00postgres\x00\x00"
startup = struct.pack("!II", 8 + len(params), 196608) + params

try:
    with socket.create_connection((host, port), timeout=5) as s:
        s.settimeout(5)
        s.sendall(startup)
        resp = s.recv(1024)
        if len(resp) >= 9 and resp[0:1] == b"R":
            auth_code = struct.unpack("!I", resp[5:9])[0]
            if auth_code == 0:
                print(f"CONFIRMED PostgreSQL trust (passwordless) auth for user 'postgres' on {host}:{port}")
                sys.exit(0)
            print(f"PostgreSQL on {host}:{port} requires auth (auth_type={auth_code})")
            sys.exit(1)
        print(f"Unexpected PostgreSQL response on {host}:{port}")
        sys.exit(1)
except Exception as e:
    print(f"PostgreSQL probe error on {host}:{port}: {e}")
    sys.exit(1)
`,
		},
		{
			Name:            "infra-mysql-empty-root-probe",
			Kind:            db.PocKindPythonScript,
			Severity:        "critical",
			Tags:            "mysql,mariadb,database,unauth,infra,intranet",
			Description:     "Probe MySQL/MariaDB (:3306) server version greeting and test whether 'root' accepts an empty password (read-only SELECT VERSION()).",
			ExploitGuidance: "Set a strong root password, disable remote root login, and restrict port 3306 to application subnets.",
			CreatedBy:       "system",
			Content: `import os, shutil, socket, subprocess, sys, urllib.parse

raw = os.environ.get("ARTEX_POC_TARGET", "").strip()
if not raw:
    print("ARTEX_POC_TARGET is required", file=sys.stderr)
    sys.exit(2)

host, port = raw, 3306
if "://" in raw:
    u = urllib.parse.urlsplit(raw)
    host = u.hostname or raw
    port = u.port or 3306
elif ":" in raw:
    h, p = raw.rsplit(":", 1)
    host = h.strip("[]")
    try:
        port = int(p)
    except ValueError:
        port = 3306

version = ""
try:
    with socket.create_connection((host, port), timeout=5) as s:
        s.settimeout(4)
        pkt = s.recv(512)
        if len(pkt) > 6 and pkt[4] == 10:
            end = pkt.find(b"\x00", 5)
            if end > 5:
                version = pkt[5:end].decode("utf-8", errors="ignore")
                print(f"mysql_greeting_version={version}")
except Exception as e:
    print(f"MySQL greeting error on {host}:{port}: {e}")
    sys.exit(1)

if shutil.which("mysql"):
    try:
        r = subprocess.run(
            ["mysql", "-h", host, "-P", str(port), "-u", "root", "--connect-timeout=5", "-N", "-e", "SELECT VERSION();"],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode == 0 and (r.stdout or "").strip():
            print(f"CONFIRMED MySQL empty root password on {host}:{port}: version={(r.stdout or '').strip()}")
            sys.exit(0)
    except Exception as e:
        print(f"mysql cli error: {e}")

print(f"MySQL root empty password rejected on {host}:{port} (version={version})")
sys.exit(1)
`,
		},
		{
			Name:            "infra-redis-sentinel-config-audit",
			Kind:            db.PocKindPythonScript,
			Severity:        "high",
			Tags:            "redis,sentinel,database,unauth,infra,intranet",
			Description:     "Read-only Redis Sentinel (:26379 SENTINEL masters) and Redis (:6379 CONFIG GET requirepass/dir) weak configuration audit.",
			ExploitGuidance: "Configure requirepass / ACLs on both Redis data nodes and Sentinel instances, and rename/disable CONFIG.",
			CreatedBy:       "system",
			Content: `import os, socket, sys, urllib.parse

raw = os.environ.get("ARTEX_POC_TARGET", "").strip()
if not raw:
    print("ARTEX_POC_TARGET is required", file=sys.stderr)
    sys.exit(2)

host, port = raw, 26379
if "://" in raw:
    u = urllib.parse.urlsplit(raw)
    host = u.hostname or raw
    port = u.port or 26379
elif ":" in raw:
    h, p = raw.rsplit(":", 1)
    host = h.strip("[]")
    try:
        port = int(p)
    except ValueError:
        port = 26379

try:
    with socket.create_connection((host, port), timeout=5) as s:
        s.settimeout(5)
        cmd = b"SENTINEL masters\r\n" if port == 26379 else b"CONFIG GET requirepass\r\nCONFIG GET dir\r\n"
        s.sendall(cmd)
        data = s.recv(4096).decode("utf-8", errors="ignore")
        if ("name" in data and "ip" in data and "port" in data) or ("requirepass" in data and "-NOAUTH" not in data):
            preview = data.replace("\r\n", " ")[:240]
            print(f"CONFIRMED Redis/Sentinel unauthenticated config/topology exposure on {host}:{port}: {preview}")
            sys.exit(0)
        print(f"Redis/Sentinel protected or non-matching response on {host}:{port}")
        sys.exit(1)
except Exception as e:
    print(f"Redis/Sentinel probe error on {host}:{port}: {e}")
    sys.exit(1)
`,
		},
		{
			Name:            "infra-clickhouse-unauth-http",
			Kind:            db.PocKindNucleiYAML,
			Severity:        "critical",
			Tags:            "clickhouse,database,unauth,infra,intranet",
			Description:     "Detect unauthenticated ClickHouse HTTP interface (:8123) executing read-only SELECT version().",
			ExploitGuidance: "Configure user passwords and IP network restrictions in ClickHouse users.xml.",
			CreatedBy:       "system",
			Content: `id: infra-clickhouse-unauth-http
info:
  name: ClickHouse Unauthenticated HTTP Interface
  severity: critical
http:
  - method: GET
    path:
      - "{{BaseURL}}/?query=SELECT%20version()"
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: regex
        regex:
          - '^[0-9]{2}\.[0-9]+\.[0-9]+'
`,
		},
		{
			Name:            "infra-couchdb-unauth-admin",
			Kind:            db.PocKindNucleiYAML,
			Severity:        "critical",
			Tags:            "couchdb,database,unauth,infra,intranet",
			Description:     "Detect unauthenticated Apache CouchDB (:5984 /_all_dbs) exposure.",
			ExploitGuidance: "Disable Admin Party mode and configure require_valid_user = true.",
			CreatedBy:       "system",
			Content: `id: infra-couchdb-unauth-admin
info:
  name: Apache CouchDB Unauthenticated Database Listing
  severity: critical
http:
  - method: GET
    path:
      - "{{BaseURL}}/_all_dbs"
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words:
          - '"_users"'
          - '"_replicator"'
        condition: or
`,
		},
		{
			Name:            "infra-influxdb-unauth-query",
			Kind:            db.PocKindNucleiYAML,
			Severity:        "high",
			Tags:            "influxdb,database,tsdb,unauth,infra,intranet",
			Description:     "Detect unauthenticated InfluxDB (:8086) query API exposing SHOW DATABASES.",
			ExploitGuidance: "Enable auth-enabled = true in influxdb.conf and bind to internal monitoring VLAN.",
			CreatedBy:       "system",
			Content: `id: infra-influxdb-unauth-query
info:
  name: InfluxDB Unauthenticated Query API
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/query?q=SHOW+DATABASES"
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words:
          - '"results"'
          - '"databases"'
        condition: and
`,
		},
		{
			Name:            "infra-openstack-keystone-api",
			Kind:            db.PocKindNucleiYAML,
			Severity:        "high",
			Tags:            "openstack,keystone,cloud,iaas,exposure,infra,intranet",
			Description:     "Detect exposed OpenStack Keystone (:5000 /v3), Glance (/v2/images), or Horizon dashboard endpoints.",
			ExploitGuidance: "Check whether public/unauthenticated image listing (/v2/images) or management APIs are exposed outside the OpenStack control plane VLAN.",
			CreatedBy:       "system",
			Content: `id: infra-openstack-keystone-api
info:
  name: OpenStack Keystone / Glance / Horizon Exposure
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/v3"
      - "{{BaseURL}}/v2/images"
      - "{{BaseURL}}/dashboard/auth/login/"
    stop-at-first-match: true
    matchers-condition: and
    matchers:
      - type: status
        status: [200, 300]
      - type: word
        words:
          - '"identity"'
          - '"openstack"'
          - 'OpenStack Dashboard'
        condition: or
`,
		},
		{
			Name:            "infra-vmware-vcenter-esxi-exposure",
			Kind:            db.PocKindNucleiYAML,
			Severity:        "medium",
			Tags:            "vmware,vcenter,esxi,virtualization,cloud,infra,intranet",
			Description:     "Detect exposed VMware vCenter / ESXi management APIs (/sdk/vimServiceVersions.xml, /mob/) and version metadata.",
			ExploitGuidance: "Restrict vCenter/ESXi management interfaces to jump-host VLANs and disable MOB (/mob/) in production.",
			CreatedBy:       "system",
			Content: `id: infra-vmware-vcenter-esxi-exposure
info:
  name: VMware vCenter / ESXi Management & MOB Exposure
  severity: medium
http:
  - method: GET
    path:
      - "{{BaseURL}}/sdk/vimServiceVersions.xml"
      - "{{BaseURL}}/mob/"
    stop-at-first-match: true
    matchers-condition: and
    matchers:
      - type: status
        status: [200, 401]
      - type: word
        words:
          - "urn:vim25"
          - "VMware"
          - "Managed Object Browser"
        condition: or
`,
		},
		{
			Name:            "infra-portainer-rancher-exposure",
			Kind:            db.PocKindNucleiYAML,
			Severity:        "high",
			Tags:            "portainer,rancher,docker,k8s,container,infra,intranet",
			Description:     "Detect exposed Portainer (/api/status, /api/users/admin/check) or Rancher (/v3-public/authProviders) container management consoles.",
			ExploitGuidance: "Verify whether Portainer admin initialization is still open (404 on /api/users/admin/check) or endpoints are exposed.",
			CreatedBy:       "system",
			Content: `id: infra-portainer-rancher-exposure
info:
  name: Portainer / Rancher Container Management Exposure
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/api/status"
      - "{{BaseURL}}/v3-public/authProviders"
    stop-at-first-match: true
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words:
          - '"InstanceID"'
          - '"authProvider"'
        condition: or
`,
		},
		{
			Name:            "infra-hashicorp-vault-status",
			Kind:            db.PocKindNucleiYAML,
			Severity:        "medium",
			Tags:            "vault,hashicorp,secrets,cloud,infra,intranet",
			Description:     "Detect exposed HashiCorp Vault (:8200 /v1/sys/health, /v1/sys/seal-status) revealing version, cluster name, and seal status.",
			ExploitGuidance: "Restrict Vault API to authorized workload subnets and audit auth methods for overly permissive tokens/roles.",
			CreatedBy:       "system",
			Content: `id: infra-hashicorp-vault-status
info:
  name: HashiCorp Vault API & Seal Status Exposure
  severity: medium
http:
  - method: GET
    path:
      - "{{BaseURL}}/v1/sys/health"
      - "{{BaseURL}}/v1/sys/seal-status"
    stop-at-first-match: true
    matchers-condition: and
    matchers:
      - type: status
        status: [200, 429, 472, 473, 501, 503]
      - type: word
        words:
          - '"sealed"'
          - '"cluster_name"'
        condition: and
`,
		},
		{
			Name:            "infra-k8s-apiserver-anon-access",
			Kind:            db.PocKindNucleiYAML,
			Severity:        "critical",
			Tags:            "kubernetes,k8s,apiserver,unauth,infra,intranet",
			Description:     "Detect Kubernetes API Server (:6443/:8080) permitting anonymous access to /api/v1/namespaces or /apis.",
			ExploitGuidance: "Disable --anonymous-auth=true or remove system:anonymous ClusterRoleBindings.",
			CreatedBy:       "system",
			Content: `id: infra-k8s-apiserver-anon-access
info:
  name: Kubernetes API Server Anonymous Access
  severity: critical
http:
  - method: GET
    path:
      - "{{BaseURL}}/api/v1/namespaces"
      - "{{BaseURL}}/api/v1/pods"
    stop-at-first-match: true
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words:
          - '"NamespaceList"'
          - '"PodList"'
        condition: or
`,
		},
		{
			Name:            "infra-zabbix-unauth-exposure",
			Kind:            db.PocKindNucleiYAML,
			Severity:        "high",
			Tags:            "zabbix,monitor,unauth,infra,intranet",
			Description:     "Detect Zabbix API version disclosure and unauthenticated Guest dashboard access.",
			ExploitGuidance: "Disable Zabbix Guest account and restrict /zabbix/ management console to O&M bastion.",
			CreatedBy:       "system",
			Content: `id: infra-zabbix-unauth-exposure
info:
  name: Zabbix Unauthenticated Guest / API Exposure
  severity: high
http:
  - method: POST
    path:
      - "{{BaseURL}}/api_jsonrpc.php"
      - "{{BaseURL}}/zabbix/api_jsonrpc.php"
    headers:
      Content-Type: application/json-rpc
    body: '{"jsonrpc":"2.0","method":"apiinfo.version","params":[],"id":1}'
    stop-at-first-match: true
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words:
          - '"jsonrpc":"2.0"'
          - '"result":'
        condition: and
`,
		},
		{
			Name:            "infra-tomcat-manager-exposure",
			Kind:            db.PocKindNucleiYAML,
			Severity:        "high",
			Tags:            "tomcat,java,middleware,manager,infra,intranet",
			Description:     "Detect exposed Apache Tomcat Manager (/manager/html) or Host Manager (/host-manager/html) interfaces.",
			ExploitGuidance: "Remove /manager and /host-manager in production or bind strictly to 127.0.0.1.",
			CreatedBy:       "system",
			Content: `id: infra-tomcat-manager-exposure
info:
  name: Apache Tomcat Manager Interface Exposure
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/manager/html"
      - "{{BaseURL}}/host-manager/html"
    stop-at-first-match: true
    matchers-condition: and
    matchers:
      - type: status
        status: [200, 401]
      - type: word
        words:
          - "Tomcat Manager Application"
          - "Tomcat Host Manager Application"
        condition: or
`,
		},
		{
			Name:            "infra-weblogic-console-exposure",
			Kind:            db.PocKindNucleiYAML,
			Severity:        "high",
			Tags:            "weblogic,oracle,java,middleware,infra,intranet",
			Description:     "Detect exposed Oracle WebLogic Admin Console (/console/login/LoginForm.jsp) and legacy SOAP endpoints.",
			ExploitGuidance: "Restrict /console to management networks and verify latest Oracle CPU patches are applied.",
			CreatedBy:       "system",
			Content: `id: infra-weblogic-console-exposure
info:
  name: Oracle WebLogic Admin Console Exposure
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/console/login/LoginForm.jsp"
      - "{{BaseURL}}/_async/AsyncResponseService"
    stop-at-first-match: true
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words:
          - "Oracle WebLogic Server"
          - "AsyncResponseService"
        condition: or
`,
		},
		{
			Name:            "infra-apollo-sentinel-unauth",
			Kind:            db.PocKindNucleiYAML,
			Severity:        "high",
			Tags:            "apollo,sentinel,spring,middleware,unauth,infra,intranet",
			Description:     "Detect unauthenticated Alibaba Sentinel Dashboard (/machine.json, /app/briefinfos.json) or Apollo config endpoints.",
			ExploitGuidance: "Enable authentication on Sentinel Dashboard and restrict config center admin APIs.",
			CreatedBy:       "system",
			Content: `id: infra-apollo-sentinel-unauth
info:
  name: Sentinel / Apollo Unauthenticated Console Exposure
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/app/briefinfos.json"
      - "{{BaseURL}}/apps"
    stop-at-first-match: true
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words:
          - '"machines"'
          - '"appId"'
        condition: or
`,
		},
	}
}
