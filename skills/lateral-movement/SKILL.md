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
2. **Tunneling / Pivoting**:
   - Establish an ephemeral SOCKS5 or port-forward tunnel using `ssh -N -D 1080 ...` or `socat` (clean up background tunnels when finished), and route targeted probes with `proxychains4 -q`.
3. **Zone Isolation Verification (`NET-BOUNDARY`)**:
   - Test reachability from the compromised DMZ/edge foothold toward internal/core subnets and management/database ports (`nmap -sT -Pn --top-ports 100` via `proxychains4`, `redis-cli`, `psql`, `mysql`, `smbclient`).
   - Record both reachable internal paths (`status="failed"`, `report_finding`) and properly segmented/blocked paths (`status="passed"`) via `record_check_result`.

## 3. MLPS Red Lines
- Never plant persistent backdoors, webshells for persistence, scheduled tasks, or new OS accounts.
- Keep pivot scans targeted and low-rate (`prod_safe_mode`).
