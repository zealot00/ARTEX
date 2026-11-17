---
name: cloud-k8s-audit
description: Safe container, Kubernetes (kubectl), and cloud metadata (IMDS) post-exploitation and lateral-movement auditing within electronic fence and lateral_gate boundaries.
---

# Cloud-Native, Container & Kubernetes Depth Audit

Use this skill when a foothold lands inside a container, Kubernetes Pod, or cloud VM during an authorized internal assessment.

## 1. Guardrails (Fence & Lateral Gate)
- Respect `fence_enabled` / `fence_rules` at all times: never pivot to external cloud control planes or unapproved VPC ranges.
- Any lateral pivot across Pods, Nodes, or host-escape attempts requires `lateral_gate` approval (`POST /api/tasks/{id}/lateral/approve`) when enabled.
- Stay strictly read-only for enumeration; do not delete Pods, mutate ClusterRoles, or exhaust node resources (`prod_safe_mode`).

## 2. Container Runtime & Escape Surface
- Detect containerization and runtime privileges:
  - `ls -la /.dockerenv /run/.containerenv` and `cat /proc/1/cgroup`
  - Capabilities: `grep CapEff /proc/self/status` (decode with `capsh --decode=...`; check `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_NET_ADMIN`, `CAP_DAC_READ_SEARCH`)
  - Mounts & host sockets: `mount | grep -E "docker.sock|containerd.sock|hostPath|cgroups"`, `ls -la /var/run/docker.sock`
  - Privileged device exposure: `ls -la /dev/sd* /dev/nvme* /dev/kmsg`
- If `docker.sock` is mounted or `CAP_SYS_ADMIN` is present, verify impact with read-only inspection (`curl --unix-socket /var/run/docker.sock http://localhost/containers/json` or `docker ps` if client exists) — never deploy persistence.

## 3. Kubernetes (kubectl) Lateral & RBAC Audit
- Locate in-cluster ServiceAccount token and API endpoint:
  - `ls -la /var/run/secrets/kubernetes.io/serviceaccount/`
  - `env | grep -i KUBERNETES`
- Check effective permissions first (non-destructive):
  - `kubectl auth can-i --list` (or `kubectl --token="$(cat .../token)" --certificate-authority=.../ca.crt --server="https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT}" auth can-i --list`)
- High-risk RBAC / workload conditions to audit:
  - `secrets` read (`get`/`list`), `pods/exec` or `pods/attach`, `pods` create (hostPath / `privileged: true` / `hostPID: true`), `nodes/proxy`, `clusterrolebindings` create/patch.
  - Check kubelet read-only/authenticated ports (`10250`/`10255`) only within authorized `fence_rules`.
- Record verified negative/positive evidence via `record_check_result` (e.g., `AUTH-ACCESS` / `SYS-CONFIG`).

## 4. Cloud Instance Metadata (IMDS) Audit
- Only probe link-local metadata (`169.254.169.254` / `100.100.100.200`) if permitted by task scope/fence:
  - Check IMDSv2 enforcement vs IMDSv1 fallback (`curl -s -m 3 http://169.254.169.254/latest/meta-data/`).
  - If IMDSv1 returns IAM role names or temporary credentials, redact secret keys before reporting (`MaskSecret` style) and report high-impact SSRF/IAM exposure.
