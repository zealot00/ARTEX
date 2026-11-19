# artex-name: infra-ntp-monlist-info
# artex-severity: medium
# artex-tags: ntp,udp,infra,misconfig,intranet
# artex-desc: Single-packet read-only UDP probe on NTP (:123) checking Mode 6 readvar info disclosure and Mode 7 monlist amplification exposure.
# artex-guidance: Recommend adding 'restrict default kod nomodify notrap nopeer noquery' and 'disable monitor' in ntp.conf.
import os, socket, sys, urllib.parse

raw = os.environ.get("ARTEX_POC_TARGET", "").strip()
if not raw:
    print("ARTEX_POC_TARGET is required", file=sys.stderr)
    sys.exit(2)

host, port = raw, 123
if "://" in raw:
    u = urllib.parse.urlsplit(raw)
    host = u.hostname or raw
    port = u.port or 123
elif ":" in raw:
    h, p = raw.rsplit(":", 1)
    host = h.strip("[]")
    try:
        port = int(p)
    except ValueError:
        port = 123

findings = []
# 1) NTP Mode 6 READVAR (control message, single small read-only packet)
mode6_req = bytes([0x16, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
# 2) NTP Mode 7 REQ_MON_GETLIST_1 (private mode 7, single packet)
mode7_req = bytes([0x17, 0x00, 0x03, 0x2a]) + b"\x00" * 44

for label, pkt in [("NTP_MODE6_READVAR", mode6_req), ("NTP_MODE7_MONLIST", mode7_req)]:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(3)
            s.sendto(pkt, (host, port))
            resp, _ = s.recvfrom(4096)
            if resp:
                preview = resp.decode("latin-1", errors="ignore").replace("\r", " ").replace("\n", " ")[:180]
                findings.append(f"{label} (bytes={len(resp)}): {preview}")
    except Exception:
        pass

if findings:
    print(f"CONFIRMED NTP control/monlist exposure on {host}:{port}:")
    for f in findings:
        print(" - " + f)
    sys.exit(0)
print(f"No NTP Mode 6/7 exposure detected on {host}:{port}")
sys.exit(1)
