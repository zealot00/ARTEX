---
name: ad-windows-audit
description: Authorized security configuration and exposure auditing for Windows services, SMB/Samba, LDAP/Active Directory, Kerberos, SNMP, and IPP/Print services under MLPS 2.0.
---

# Windows, Directory Service & Print Service Audit

Use this skill for MLPS checks `AD-DIR` and `WIN-SVC` during authorized internal/external security assessments.

## 1. Non-Intrusive Port & Protocol Discovery
- Identify directory, file-sharing, management, and print ports safely:
  `nmap -sV -Pn -p 135,139,161,389,445,631,636,3268,3389,5985,5986 <target>`

## 2. SMB / Samba & Print Service Checks (`WIN-SVC`)
- **SMB signing & dialect check**:
  `nmap -p 445 --script smb2-security-mode,smb-protocols <target>`
- **Anonymous share listing**:
  `smbclient -L //<target> -N`
- **Print service (IPP / CUPS / Spooler) exposure check**:
  - Check TCP 631 (`ippfind` or `curl -skI https://<target>:631/`) and RPC/SMB print exposure (`nmap -p 445 --script smb-enum-shares <target>`).
  - Verify unnecessary print services are disabled or restricted to authorized management VLANs.
- Record findings or verified negative compliance (`status="passed"`) via `record_check_result(check_code="WIN-SVC", ...)`.

## 3. LDAP / Active Directory Baseline Checks (`AD-DIR`)
- **Anonymous LDAP bind check**:
  `ldapsearch -x -H ldap://<target>:389 -s base namingContexts`
- **LDAPS / StartTLS check** (`NET-TLS` + `AD-DIR`):
  `sslscan --no-colour <target>:636`
- **Account lockout safety**: never run password spraying against domain controllers without checking lockout thresholds first; respect `prod_safe_mode`.
  - When conducting authorized domain password spraying, use `run_password_spray(task_id=..., target=..., protocol="smb"|"ldap"|"winrm", user_list=..., pass_list=..., start_offset=0, max_passwords=1, delay_seconds=2)` instead of `hydra` or raw `nxc` with plaintext password files. It enforces the electronic fence, `lateral_gate`, inter-round lockout delay, and password masking.
- If `lateral_gate` is enabled, wait for foothold approval (`POST /api/tasks/{id}/lateral/approve`) before running directory graph collection (`bloodhound-python`), ADCS auditing (`certipy`), DNS enumeration (`adidnsdump`), or credentialed `nxc` / `impacket-*` tools.
- Record all verified outcomes (including `"passed"` and `"na"` for Linux-only environments) via `record_check_result(check_code="AD-DIR", ...)`.
