package server

import "github.com/Autumn-27/artex/db"

func extraInfraPocs() []db.UpsertPocInput {
	return []db.UpsertPocInput{
		{
			Name:            "infra-mongodb-unauth-probe",
			Kind:            db.PocKindPythonScript,
			Severity:        "critical",
			Tags:            "mongodb,database,unauth,infra,intranet",
			Description:     "Pure-TCP BSON OP_MSG read-only probe checking whether MongoDB (:27017) permits unauthenticated listDatabases.",
			ExploitGuidance: "Report exposed database names as read-only proof; enable security.authorization: enabled in mongod.conf.",
			CreatedBy:       "system",
			Content: `import os, socket, struct, sys, urllib.parse

raw = os.environ.get("ARTEX_POC_TARGET", "").strip()
if not raw:
    print("ARTEX_POC_TARGET is required", file=sys.stderr)
    sys.exit(2)

host, port = raw, 27017
if "://" in raw:
    u = urllib.parse.urlsplit(raw)
    host = u.hostname or raw
    port = u.port or 27017
elif ":" in raw:
    h, p = raw.rsplit(":", 1)
    host = h.strip("[]")
    try:
        port = int(p)
    except ValueError:
        port = 27017

# Build minimal BSON doc: { "listDatabases": 1, "$db": "admin" }
def bson_int32(k, v):
    return b"\x10" + k.encode() + b"\x00" + struct.pack("<i", v)

def bson_str(k, v):
    vb = v.encode() + b"\x00"
    return b"\x02" + k.encode() + b"\x00" + struct.pack("<i", len(vb)) + vb

doc_body = bson_int32("listDatabases", 1) + bson_str("$db", "admin") + b"\x00"
doc = struct.pack("<i", len(doc_body) + 4) + doc_body
# OP_MSG (2013): header (16 bytes) + flagBits (4) + kind=0 (1) + doc
payload = struct.pack("<I", 0) + b"\x00" + doc
header = struct.pack("<iiii", 16 + len(payload), 1, 0, 2013)

try:
    with socket.create_connection((host, port), timeout=5) as s:
        s.settimeout(5)
        s.sendall(header + payload)
        resp = s.recv(4096)
        text = resp.decode("latin-1", errors="ignore")
        if "databases" in text and "totalSize" in text and "Unauthorized" not in text:
            print(f"CONFIRMED MongoDB unauthenticated listDatabases on {host}:{port} (resp_bytes={len(resp)})")
            sys.exit(0)
        print(f"MongoDB requires authentication or non-MongoDB response on {host}:{port}")
        sys.exit(1)
except Exception as e:
    print(f"MongoDB probe error on {host}:{port}: {e}")
    sys.exit(1)
`,
		},
		{
			Name:            "infra-zookeeper-unauth-4lw",
			Kind:            db.PocKindPythonScript,
			Severity:        "high",
			Tags:            "zookeeper,bigdata,unauth,infra,intranet",
			Description:     "Pure-TCP read-only probe checking ZooKeeper (:2181) unauthenticated four-letter words (ruok / stat / envi).",
			ExploitGuidance: "Restrict 4lw.commands.whitelist and enforce SASL/firewall isolation on port 2181.",
			CreatedBy:       "system",
			Content: `import os, socket, sys, urllib.parse

raw = os.environ.get("ARTEX_POC_TARGET", "").strip()
if not raw:
    print("ARTEX_POC_TARGET is required", file=sys.stderr)
    sys.exit(2)

host, port = raw, 2181
if "://" in raw:
    u = urllib.parse.urlsplit(raw)
    host = u.hostname or raw
    port = u.port or 2181
elif ":" in raw:
    h, p = raw.rsplit(":", 1)
    host = h.strip("[]")
    try:
        port = int(p)
    except ValueError:
        port = 2181

hits = []
for cmd in ("ruok", "stat", "envi"):
    try:
        with socket.create_connection((host, port), timeout=4) as s:
            s.settimeout(4)
            s.sendall(cmd.encode("ascii"))
            data = s.recv(2048).decode("utf-8", errors="ignore").strip()
            if data and ("imok" in data or "Zookeeper version:" in data or "Environment:" in data):
                first_line = data.splitlines()[0][:160]
                hits.append(f"{cmd} -> {first_line}")
    except Exception:
        pass

if hits:
    print(f"CONFIRMED ZooKeeper unauthenticated 4lw on {host}:{port}: " + " | ".join(hits))
    sys.exit(0)
print(f"No unauthenticated ZooKeeper 4lw response on {host}:{port}")
sys.exit(1)
`,
		},
		{
			Name:            "infra-kafka-ui-akhq-exposure",
			Kind:            db.PocKindNucleiYAML,
			Severity:        "high",
			Tags:            "kafka,mq,bigdata,unauth,infra,intranet",
			Description:     "Detect unauthenticated Kafka-UI, AKHQ, or Kafka-Manager (CMAK) web management consoles.",
			ExploitGuidance: "Inspect exposed cluster/topic names only; enforce SSO/RBAC authentication on Kafka management UIs.",
			CreatedBy:       "system",
			Content: `id: infra-kafka-ui-akhq-exposure
info:
  name: Kafka UI / AKHQ / CMAK Unauthenticated Exposure
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/api/clusters"
      - "{{BaseURL}}/ui/clusters"
      - "{{BaseURL}}/api/me"
    stop-at-first-match: true
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words:
          - '"brokerCount"'
          - '"topicCount"'
          - '"bootstrapServers"'
        condition: or
`,
		},
		{
			Name:            "infra-hadoop-yarn-hdfs-unauth",
			Kind:            db.PocKindNucleiYAML,
			Severity:        "critical",
			Tags:            "hadoop,yarn,hdfs,bigdata,unauth,infra,intranet",
			Description:     "Detect unauthenticated Hadoop YARN ResourceManager (:8088) or HDFS NameNode (:9870) REST/Web UIs.",
			ExploitGuidance: "Verify read-only cluster/node info via /ws/v1/cluster/info or /jmx; do not submit applications in production.",
			CreatedBy:       "system",
			Content: `id: infra-hadoop-yarn-hdfs-unauth
info:
  name: Hadoop YARN / HDFS Unauthenticated Exposure
  severity: critical
http:
  - method: GET
    path:
      - "{{BaseURL}}/ws/v1/cluster/info"
      - "{{BaseURL}}/jmx?qry=Hadoop:service=NameNode,name=NameNodeInfo"
    stop-at-first-match: true
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words:
          - '"clusterInfo"'
          - '"hadoopVersion"'
          - 'Hadoop:service=NameNode'
        condition: or
`,
		},
		{
			Name:            "infra-spark-flink-unauth",
			Kind:            db.PocKindNucleiYAML,
			Severity:        "high",
			Tags:            "spark,flink,bigdata,unauth,infra,intranet",
			Description:     "Detect unauthenticated Apache Spark Master UI or Apache Flink Dashboard (/overview, /config).",
			ExploitGuidance: "Verify read-only cluster overview (/overview, /jobs/overview); do not upload JARs or submit jobs.",
			CreatedBy:       "system",
			Content: `id: infra-spark-flink-unauth
info:
  name: Apache Spark / Flink Unauthenticated Dashboard
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/overview"
      - "{{BaseURL}}/json/"
    stop-at-first-match: true
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words:
          - '"flink-version"'
          - '"taskmanagers"'
          - '"aliveworkers"'
        condition: or
`,
		},
		{
			Name:            "infra-rabbitmq-management-exposure",
			Kind:            db.PocKindNucleiYAML,
			Severity:        "high",
			Tags:            "rabbitmq,mq,default-login,infra,intranet",
			Description:     "Detect RabbitMQ Management API (:15672) accepting default guest:guest credentials on /api/overview.",
			ExploitGuidance: "Report RabbitMQ version and cluster name; remove or rotate guest user and restrict management port.",
			CreatedBy:       "system",
			Content: `id: infra-rabbitmq-management-exposure
info:
  name: RabbitMQ Management Default Guest Access
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/api/overview"
    headers:
      Authorization: Basic Z3Vlc3Q6Z3Vlc3Q=
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words:
          - '"rabbitmq_version"'
          - '"management_version"'
        condition: and
`,
		},
		{
			Name:            "infra-gitlab-public-explore",
			Kind:            db.PocKindNucleiYAML,
			Severity:        "medium",
			Tags:            "gitlab,git,ci,exposure,infra,intranet",
			Description:     "Detect internal GitLab instances exposing public project repositories or user directories without authentication.",
			ExploitGuidance: "Review exposed internal repo names via /api/v4/projects for unintended source/secret visibility.",
			CreatedBy:       "system",
			Content: `id: infra-gitlab-public-explore
info:
  name: Internal GitLab Unauthenticated Public Projects Exposure
  severity: medium
http:
  - method: GET
    path:
      - "{{BaseURL}}/api/v4/projects?per_page=5"
      - "{{BaseURL}}/api/v4/users?per_page=5"
    stop-at-first-match: true
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words:
          - '"path_with_namespace"'
          - '"http_url_to_repo"'
        condition: and
`,
		},
		{
			Name:            "infra-nexus-artifactory-unauth",
			Kind:            db.PocKindNucleiYAML,
			Severity:        "medium",
			Tags:            "nexus,artifactory,ci,registry,unauth,infra,intranet",
			Description:     "Detect unauthenticated Sonatype Nexus or JFrog Artifactory repository listing endpoints.",
			ExploitGuidance: "Verify whether internal proprietary packages or build artifacts are downloadable anonymously.",
			CreatedBy:       "system",
			Content: `id: infra-nexus-artifactory-unauth
info:
  name: Nexus / Artifactory Unauthenticated Repository Exposure
  severity: medium
http:
  - method: GET
    path:
      - "{{BaseURL}}/service/rest/v1/repositories"
      - "{{BaseURL}}/artifactory/api/repositories"
    stop-at-first-match: true
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words:
          - '"format"'
          - '"packageType"'
        condition: or
`,
		},
		{
			Name:            "infra-sonarqube-unauth-exposure",
			Kind:            db.PocKindNucleiYAML,
			Severity:        "medium",
			Tags:            "sonarqube,ci,code,unauth,infra,intranet",
			Description:     "Detect unauthenticated SonarQube API (/api/projects/search, /api/issues/search) exposing internal project names and code issues.",
			ExploitGuidance: "Enable 'Force user authentication' in SonarQube security settings.",
			CreatedBy:       "system",
			Content: `id: infra-sonarqube-unauth-exposure
info:
  name: SonarQube Unauthenticated Project Exposure
  severity: medium
http:
  - method: GET
    path:
      - "{{BaseURL}}/api/projects/search?ps=5"
      - "{{BaseURL}}/api/components/search?qualifiers=TRK&ps=5"
    stop-at-first-match: true
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words:
          - '"components"'
          - '"paging"'
        condition: and
`,
		},
		{
			Name:            "infra-kibana-unauth-exposure",
			Kind:            db.PocKindNucleiYAML,
			Severity:        "high",
			Tags:            "kibana,elk,monitor,unauth,infra,intranet",
			Description:     "Detect unauthenticated Kibana status/saved-objects API exposure.",
			ExploitGuidance: "Check whether Kibana allows anonymous log search or index pattern inspection.",
			CreatedBy:       "system",
			Content: `id: infra-kibana-unauth-exposure
info:
  name: Kibana Unauthenticated API Exposure
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/api/status"
      - "{{BaseURL}}/api/saved_objects/_find?type=index-pattern&per_page=5"
    stop-at-first-match: true
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words:
          - '"kibana"'
          - '"saved_objects"'
        condition: or
`,
		},
		{
			Name:            "infra-xxljob-admin-exposure",
			Kind:            db.PocKindNucleiYAML,
			Severity:        "medium",
			Tags:            "xxljob,java,scheduler,infra,intranet",
			Description:     "Detect exposed XXL-JOB Admin console or unauthenticated executor /beat endpoint.",
			ExploitGuidance: "Check if XXL-JOB executor accessToken is unset (default empty) or admin uses default admin/123456.",
			CreatedBy:       "system",
			Content: `id: infra-xxljob-admin-exposure
info:
  name: XXL-JOB Admin / Executor Exposure
  severity: medium
http:
  - method: GET
    path:
      - "{{BaseURL}}/xxl-job-admin/toLogin"
      - "{{BaseURL}}/toLogin"
    stop-at-first-match: true
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words:
          - "XXL-JOB"
          - "jobinfo"
        condition: or
`,
		},
		{
			Name:            "infra-eureka-consul-unauth",
			Kind:            db.PocKindNucleiYAML,
			Severity:        "high",
			Tags:            "eureka,consul,spring,service-mesh,unauth,infra,intranet",
			Description:     "Detect unauthenticated Spring Cloud Eureka (/eureka/apps) or HashiCorp Consul (/v1/agent/self, /v1/catalog/services) registries.",
			ExploitGuidance: "Enumerate registered internal microservices and check if Consul KV store exposes secrets.",
			CreatedBy:       "system",
			Content: `id: infra-eureka-consul-unauth
info:
  name: Eureka / Consul Unauthenticated Service Registry Exposure
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/eureka/apps"
      - "{{BaseURL}}/v1/agent/self"
      - "{{BaseURL}}/v1/catalog/services"
    stop-at-first-match: true
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words:
          - "<applications>"
          - '"Member"'
          - '"consul"'
        condition: or
`,
		},
		{
			Name:            "infra-minio-console-metrics",
			Kind:            db.PocKindNucleiYAML,
			Severity:        "medium",
			Tags:            "minio,s3,storage,exposure,infra,intranet",
			Description:     "Detect exposed MinIO cluster metrics (/minio/v2/metrics/cluster) or health/console endpoints.",
			ExploitGuidance: "Verify whether cluster metrics or anonymous S3 buckets expose internal object listings.",
			CreatedBy:       "system",
			Content: `id: infra-minio-console-metrics
info:
  name: MinIO Cluster Metrics / API Exposure
  severity: medium
http:
  - method: GET
    path:
      - "{{BaseURL}}/minio/v2/metrics/cluster"
      - "{{BaseURL}}/minio/prometheus/metrics"
    stop-at-first-match: true
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words:
          - "minio_cluster_"
          - "minio_s3_"
        condition: or
`,
		},
		{
			Name:            "infra-nginx-apache-status-leak",
			Kind:            db.PocKindNucleiYAML,
			Severity:        "low",
			Tags:            "nginx,apache,phpinfo,status,exposure,infra,intranet",
			Description:     "Detect exposed Nginx stub_status, Apache server-status, or phpinfo diagnostic pages.",
			ExploitGuidance: "Restrict status pages to 127.0.0.1 and remove phpinfo files from web roots.",
			CreatedBy:       "system",
			Content: `id: infra-nginx-apache-status-leak
info:
  name: Nginx / Apache Status or PHPInfo Exposure
  severity: low
http:
  - method: GET
    path:
      - "{{BaseURL}}/nginx_status"
      - "{{BaseURL}}/stub_status"
      - "{{BaseURL}}/server-status"
      - "{{BaseURL}}/phpinfo.php"
    stop-at-first-match: true
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words:
          - "Active connections:"
          - "Apache Server Status"
          - "PHP Version"
        condition: or
`,
		},
		{
			Name:            "infra-tls-weak-protocol-cipher",
			Kind:            db.PocKindPythonScript,
			Severity:        "medium",
			Tags:            "tls,ssl,crypto,mlps,infra,intranet",
			Description:     "Audit TLS endpoint for deprecated SSLv3/TLSv1.0/TLSv1.1 protocols or weak RC4/3DES/EXPORT ciphers using sslscan.",
			ExploitGuidance: "Record verified TLS posture under NET-TLS (MLPS 2.0); enforce TLSv1.2+ with AEAD ciphers.",
			CreatedBy:       "system",
			Content: `import os, shutil, subprocess, sys, urllib.parse

raw = os.environ.get("ARTEX_POC_TARGET", "").strip()
if not raw:
    print("ARTEX_POC_TARGET is required", file=sys.stderr)
    sys.exit(2)

if not shutil.which("sslscan"):
    print("sslscan binary not installed", file=sys.stderr)
    sys.exit(1)

target = raw
if "://" in raw:
    u = urllib.parse.urlsplit(raw)
    port = u.port or 443
    target = f"{u.hostname}:{port}"

try:
    r = subprocess.run(["sslscan", "--no-colour", target], capture_output=True, text=True, timeout=25)
    out = r.stdout or ""
    issues = []
    for line in out.splitlines():
        s = line.strip()
        if any(p in s for p in ("SSLv2   enabled", "SSLv3   enabled", "TLSv1.0   enabled", "TLSv1.1   enabled")):
            issues.append(s)
        if ("Accepted" in s or "Preferred" in s) and any(w in s.upper() for w in ("RC4", "DES-CBC3", "EXP", "NULL", "MD5")):
            issues.append(s)
    if issues:
        print(f"CONFIRMED weak TLS config on {target}:")
        for i in issues[:12]:
            print(" - " + i)
        sys.exit(0)
    print(f"TLS configuration on {target} shows no SSLv2/v3/TLSv1.0/v1.1 or weak ciphers")
    sys.exit(1)
except Exception as e:
    print(f"sslscan error: {e}")
    sys.exit(1)
`,
		},
	}
}
