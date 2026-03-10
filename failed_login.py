#!/usr/bin/env python3
import argparse
import subprocess
import sys
import re
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import List, Dict, Tuple, Optional

# Hardcode tshark path for Windows (your install)
TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"

# --- FTP parsing helpers ---
RX_USER = re.compile(r"(?im)^\s*USER\s+(?P<user>[^\r\n\s]+)")
RX_PASS = re.compile(r"(?im)^\s*PASS\s+(?P<pwd>[^\r\n\s]+)")
RX_530  = re.compile(r"(?im)^\s*530\b.*")  # 530 Authentication failed, etc.

@dataclass
class Hit:
    ts: float
    src_ip: str
    dst_ip: str
    user: str
    stream: str
    line: str

def run_tshark(pcap_path: str, display_filter: str) -> subprocess.Popen:
    """
    Extract:
      - frame.time_epoch
      - ip.src / ip.dst
      - tcp.stream
      - tcp.payload (hex)
    """
    cmd = [
        TSHARK_PATH,
        "-r", pcap_path,
        "-Y", display_filter,
        "-T", "fields",
        "-E", "separator=\t",
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "tcp.stream",
        "-e", "tcp.payload",
    ]
    try:
        return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except FileNotFoundError:
        print(f"ERROR: tshark not found at: {TSHARK_PATH}", file=sys.stderr)
        sys.exit(2)

def hex_payload_to_text(hex_payload: str) -> str:
    if not hex_payload:
        return ""
    cleaned = hex_payload.replace(":", "").strip()
    if not cleaned:
        return ""
    try:
        b = bytes.fromhex(cleaned)
    except ValueError:
        return ""
    return b.decode("utf-8", errors="replace")

def detect_three_total(hits: List[Hit]) -> Dict[Tuple[str, str], List[Hit]]:
    grouped: Dict[Tuple[str, str], List[Hit]] = defaultdict(list)
    for h in hits:
        grouped[(h.user, h.src_ip)].append(h)
    return {k: v for k, v in grouped.items() if len(v) >= 3}

def detect_bursts(hits: List[Hit], window_seconds: int = 300, threshold: int = 3) -> Dict[Tuple[str, str], List[List[Hit]]]:
    grouped: Dict[Tuple[str, str], List[Hit]] = defaultdict(list)
    for h in hits:
        grouped[(h.user, h.src_ip)].append(h)

    bursts: Dict[Tuple[str, str], List[List[Hit]]] = defaultdict(list)

    for key, lst in grouped.items():
        lst.sort(key=lambda x: x.ts)
        dq: deque[Hit] = deque()
        for h in lst:
            dq.append(h)
            while dq and (h.ts - dq[0].ts) > window_seconds:
                dq.popleft()
            if len(dq) >= threshold:
                bursts[key].append(list(dq))
                dq.popleft()
    return bursts

def main():
    ap = argparse.ArgumentParser(description="Detect failed FTP logins (530 responses) in a PCAP using tshark.")
    ap.add_argument("pcap", help="Path to .pcap or .pcapng file")
    ap.add_argument("--filter", default="tcp.port==2121", help="tshark display filter (default: tcp.port==2121)")
    ap.add_argument("--window", type=int, default=300, help="Burst window in seconds (default: 300)")
    ap.add_argument("--threshold", type=int, default=3, help="How many failures trigger (default: 3)")
    args = ap.parse_args()

    proc = run_tshark(args.pcap, args.filter)
    assert proc.stdout is not None
    assert proc.stderr is not None

    # Track last USER seen per tcp.stream
    last_user_by_stream: Dict[str, str] = {}

    hits: List[Hit] = []

    for line in proc.stdout:
        line = line.rstrip("\n")
        if not line:
            continue

        parts = line.split("\t")
        while len(parts) < 5:
            parts.append("")

        ts_s, src_ip, dst_ip, stream, payload_hex = parts[0], parts[1], parts[2], parts[3], parts[4]
        if not ts_s or not stream:
            continue
        try:
            ts = float(ts_s)
        except ValueError:
            continue

        text = hex_payload_to_text(payload_hex)
        if not text:
            continue

        # Normalize into lines (FTP is CRLF line-based)
        for l in text.splitlines():
            l = l.strip()
            if not l:
                continue

            m_user = RX_USER.search(l)
            if m_user:
                last_user_by_stream[stream] = m_user.group("user")
                continue

            # If server says 530, count as a failed login for the last USER in this stream
            if RX_530.search(l) and "Authentication failed" in l:
                user = last_user_by_stream.get(stream, "UNKNOWN")
                hits.append(Hit(ts=ts, src_ip=src_ip, dst_ip=dst_ip, user=user, stream=stream, line=l))

    stderr = proc.stderr.read()
    rc = proc.wait()
    if rc != 0 and stderr:
        print("tshark error output:", file=sys.stderr)
        print(stderr, file=sys.stderr)

    if not hits:
        print("No FTP failed-login (530) events found.")
        print("Tip: confirm you used --filter tcp.port==2121 (or whatever port your FTP server used).")
        return

    # Print all failures (useful for your lab writeup)
    print("\n=== FTP 530 Failures (raw) ===")
    hits.sort(key=lambda h: h.ts)
    for h in hits[:50]:
        print(f"ts={h.ts:.6f} stream={h.stream} user={h.user} src={h.src_ip} dst={h.dst_ip} msg='{h.line}'")
    if len(hits) > 50:
        print(f"... ({len(hits)-50} more)")

    total_flagged = detect_three_total(hits)
    if total_flagged:
        print("\n=== 3+ Failed Logins (Total) ===")
        for (user, src_ip), lst in sorted(total_flagged.items(), key=lambda kv: (-len(kv[1]), kv[0][0], kv[0][1])):
            print(f"User={user}  SrcIP={src_ip}  Count={len(lst)}")

    bursts = detect_bursts(hits, window_seconds=args.window, threshold=args.threshold)
    if bursts:
        print(f"\n=== Bursts: {args.threshold}+ Failures within {args.window}s ===")
        for (user, src_ip), burst_lists in bursts.items():
            print(f"User={user} SrcIP={src_ip} BurstsFound={len(burst_lists)}")
            for i, bl in enumerate(burst_lists[:10], start=1):
                print(f"  Burst #{i}: count={len(bl)} start={bl[0].ts:.6f} end={bl[-1].ts:.6f}")

if __name__ == "__main__":
    main()
