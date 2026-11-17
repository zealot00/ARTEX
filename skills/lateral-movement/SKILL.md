---
name: lateral-movement
description: Post-foothold internal network discovery, SOCKS/port-forward pivoting, and MLPS zone-isolation verification after a foothold vulnerability is confirmed and approved.
---

# Lateral Movement & Zone-Isolation Verification

Use this skill ONLY after a qualifying foothold vulnerability (e.g. RCE, SSRF, leaked SSH/DB/API credentials, or unauthorized admin panel) is confirmed **and** lateral execution is approved (`lateral_approved = true`).

## 1. Preconditions & Gate Rules
- If the task has `lateral_gate = true` and `lateral_approved = false`, lateral pivot/tunnel tools (`proxychains4`, `socat`, `ssh -D/-L/-R`, `chisel`, `impacket`, `netexec`) are blocked by the platform guard to prevent premature or wasted exploration.
- Wait for the foothold finding and approval (`POST /api/tasks/{id}/lateral/approve`) before executing pivot steps.

## 2. Non-Destructive Post-Foothold Discovery
1. **Local host context** (through the confirmed foothold):
   - Inspect interfaces/routes (`ip addr`, `ip route`), `/etc/hosts`, `/etc/resolv.conf`, active connections (`ss -tulpn`), and environment/config credentials without modifying system files.
2. **Persistent Sessions, Multi-Hop Pivoting & Tunnels**:
   - **Task-scoped persistent sessions (`depth_session_open` / `depth_session_exec` / `depth_session_list` / `depth_session_close`)**:
     - Use `kind="ssh"` with `socks_port=-1` (auto local SOCKS5 listener) and optional `credential_id` (resolves `task_credentials` server-side without exposing passwords) to maintain a persistent SSH jump session and SOCKS5 pivot.
     - Chain multi-hop pivots cleanly with `jump_session_id="<hop1_session_id>"`.
     - Use `kind="pty"` for persistent interactive shells (`kubectl exec -it`, `evil-winrm`, `impacket-wmiexec`) or `kind="tunnel"` for `chisel` / `socat` background tunnels; all open sessions are visible via `GET /api/tasks/{id}/sessions` and auto-cleaned when the task ends.
   - **Chisel reverse/SOCKS5 tunnel** (preinstalled `chisel`) when SSH forwarding is unavailable across NAT/firewalls:
     `chisel server -p <port> --socks5` / `chisel client <server> R:socks`, then route targeted probes with `proxychains4 -q`.
   - **Impacket & NetExec lateral execution** (only after `lateral_gate` approval):
     - `nxc smb <target> -u <user> -H <ntlm_hash>` (Pass-the-Hash) or `-k` (Kerberos `.ccache`), `--shares`, `--sessions`
     - `impacket-wmiexec` / `impacket-psexec` / `impacket-secretsdump` (non-destructive verification only; redact secrets in findings).
3. **Zone Isolation Verification (`NET-BOUNDARY`)**:
   - Test reachability from the compromised DMZ/edge foothold toward internal/core subnets and management/database ports (`nmap -sT -Pn --top-ports 100` via `proxychains4`, `redis-cli`, `psql`, `mysql`, `smbclient`).
   - Record both reachable internal paths (`status="failed"`, `report_finding`) and properly segmented/blocked paths (`status="passed"`) via `record_check_result`.

## 3. MLPS Red Lines
- Never plant persistent backdoors, webshells for persistence, scheduled tasks, or new OS accounts.
- Keep pivot scans targeted and low-rate (`prod_safe_mode`).
