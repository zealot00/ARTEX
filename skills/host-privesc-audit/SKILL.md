---
name: host-privesc-audit
description: Systematic, non-destructive Linux and Windows local privilege-escalation enumeration after obtaining a foothold.
---

# Host Privilege-Escalation Audit

Use this skill after confirming a low-privilege foothold on a Linux or Windows host to systematically evaluate local privilege-escalation paths without destabilizing production systems.

## 1. Safety Rules
- Read-only enumeration first. Never overwrite system binaries, drop kernel exploits that can panic the host, or modify `/etc/passwd` / `sudoers` / Windows SAM in `prod_safe_mode`.
- Redact any discovered plaintext passwords, private keys, or tokens before recording evidence or findings.

## 2. Linux Privilege-Escalation Checklist
1. **Identity & Sudo**: `id`, `sudo -l` (check `NOPASSWD`, `LD_PRELOAD`/`env_keep`, wildcard abuse).
2. **SUID / SGID & Capabilities**:
   - `find / -perm -4000 -type f 2>/dev/null`
   - `getcap -r / 2>/dev/null`
3. **Writable Services, Cron & PATH**:
   - `ls -la /etc/cron* /var/spool/cron/crontabs/ 2>/dev/null`
   - `systemctl list-units --type=service --state=running` + check unit file permissions (`find /etc/systemd/system -writable 2>/dev/null`).
4. **Local Ports & Credential Hygiene**:
   - `ss -tulpn` (identify localhost-only DBs, Redis, admin panels, Docker/kubelet sockets).
   - Inspect config/env permissions (`ls -la ~/.ssh`, `/opt`, `/var/www`, `env` — report exposure without printing full secrets).
5. **Kernel & OS Patch Level**: `uname -a`, `/etc/os-release` (flag known-vulnerable EOL kernels with CVE references rather than running crash-prone PoCs).

## 3. Windows Privilege-Escalation Checklist
1. **Token & Group Privileges**: `whoami /priv` (look for `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`, `SeBackupPrivilege`, `SeRestorePrivilege`, `SeDebugPrivilege`) and `whoami /groups`.
2. **Service & Scheduled Task Misconfigurations**:
   - Unquoted service paths: `wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\"`
   - Weak service/binary ACLs via `icacls` / `sc qc <svc>` / `accesschk` (read-only check).
3. **Registry & Installer Settings**:
   - `AlwaysInstallElevated`: `reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated` and `HKCU\...`
   - Stored creds (`cmdkey /list`, `Unattend.xml`, PowerShell history `ConsoleHost_history.txt`).
4. **Network & Local Bindings**: `netstat -ano` (find internal-only admin services for local port forwarding after `lateral_gate` approval).
