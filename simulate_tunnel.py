"""
DNS tunnel traffic simulator — for academic / lab testing of
dns_tunnel_cli.py against realistic exfiltration-style traffic.

Mimics the on-the-wire behavior of tools like iodine / dnscat2:
  - long, high-entropy labels packed near the 63-char DNS label limit
  - multi-label stacking to push total qname length toward 253 chars
  - heavy bias to TXT / NULL / ANY queries (carry the most response bytes)
  - high sustained query rate with tight inter-arrival times
  - burst windows interleaved with brief lulls (typical of chunked exfil)
  - unique qname per query (no caching = forces resolver round-trips)

Default target is 127.0.0.1:53 (loopback). No DNS server needs to be
listening — packets still hit the wire and your sniffer captures them.

Authorized use only: run this against your own host / lab environment.
"""

from __future__ import annotations

import argparse
import base64
import os
import random
import socket
import string
import subprocess
import sys
import time

from scapy.all import DNS, DNSQR  # type: ignore


# Heavier weighting on suspicious record types real tunnels rely on.
SUSPICIOUS_TYPES = [
    ("TXT", 16, 0.55),    # dnscat2 / iodine primary channel
    ("NULL", 10, 0.20),   # iodine raw-data channel
    ("ANY", 255, 0.10),
    ("CNAME", 5, 0.10),
    ("MX", 15, 0.05),
]

# DNS protocol limits.
MAX_LABEL_LEN = 63
MAX_QNAME_LEN = 250  # leave headroom under 253 for the base domain

# base64 url-safe charset (no padding) — what most tunnel encoders use.
B64_ALPHABET = string.ascii_lowercase + string.digits + "-"


def _detect_system_dns() -> str | None:
    """Return the first IPv4 DNS resolver configured on the host, if any.

    Loopback (127.0.0.1) is never returned because traffic to localhost does
    not cross a real network adapter on Windows and would not be visible to
    a sniffer attached to Wi-Fi/Ethernet.
    """
    try:
        if sys.platform.startswith("win"):
            output = subprocess.check_output(
                ["powershell", "-NoProfile", "-Command",
                 "(Get-DnsClientServerAddress -AddressFamily IPv4 "
                 "| Where-Object { $_.ServerAddresses } "
                 "| Select-Object -ExpandProperty ServerAddresses) -join ','"],
                stderr=subprocess.DEVNULL, timeout=5,
            ).decode("utf-8", errors="ignore")
            candidates = [item.strip() for item in output.split(",") if item.strip()]
        else:
            with open("/etc/resolv.conf", "r", encoding="utf-8") as handle:
                candidates = [
                    line.split()[1]
                    for line in handle
                    if line.startswith("nameserver") and len(line.split()) >= 2
                ]
    except Exception:
        return None

    for address in candidates:
        if address and not address.startswith("127.") and ":" not in address:
            return address
    return None


def _weighted_choice() -> tuple[str, int]:
    r = random.random()
    cumulative = 0.0
    for name, qtype, weight in SUSPICIOUS_TYPES:
        cumulative += weight
        if r <= cumulative:
            return name, qtype
    return "TXT", 16


def _encoded_label(target_len: int) -> str:
    """Generate one DNS label of ~target_len chars, base64-style, high entropy."""
    target_len = min(target_len, MAX_LABEL_LEN)
    raw_bytes_needed = (target_len * 6 + 7) // 8
    raw = os.urandom(raw_bytes_needed)
    encoded = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=").lower()
    encoded = encoded.replace("_", "-")
    return encoded[:target_len]


def _build_tunnel_qname(base_domain: str, label_depth: int, label_size: int) -> str:
    labels = [_encoded_label(label_size) for _ in range(label_depth)]
    qname = ".".join(labels) + "." + base_domain
    if len(qname) > MAX_QNAME_LEN:
        qname = qname[:MAX_QNAME_LEN].rstrip(".")
    return qname


def _craft_query(qname: str, qtype: int) -> bytes:
    transaction_id = random.randint(0, 0xFFFF)
    pkt = DNS(id=transaction_id, rd=1, qd=DNSQR(qname=qname, qtype=qtype))
    return bytes(pkt)


def _benign_qname() -> str:
    word = "".join(random.choices(string.ascii_lowercase, k=random.randint(4, 9)))
    tld = random.choice(["com", "net", "org", "io", "co"])
    return f"{word}.{tld}"


def _next_query(base_domain: str, label_depth: int, label_size: int, benign_ratio: float) -> tuple[str, int, str, bool]:
    if random.random() < benign_ratio:
        return _benign_qname(), 1, "benign", False
    qname = _build_tunnel_qname(base_domain, label_depth, label_size)
    type_name, qtype = _weighted_choice()
    return qname, qtype, f"tunnel/{type_name}", True


def _pace(interval: float) -> None:
    if interval <= 0:
        return
    jitter = random.uniform(-0.2, 0.2) * interval
    time.sleep(max(0.0, interval + jitter))


def _maybe_burst_pause(next_pause: float | None) -> float | None:
    if next_pause is None or time.time() < next_pause:
        return next_pause
    time.sleep(random.uniform(0.3, 0.8))
    return time.time() + random.uniform(2.0, 5.0)


def run(
    target_ip: str,
    target_port: int,
    duration: float,
    rate: float,
    base_domain: str,
    benign_ratio: float,
    label_depth: int,
    label_size: int,
    burst: bool,
) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)

    interval = 1.0 / rate if rate > 0 else 0.0
    end_time = time.time() + duration
    sent = 0
    tunnel_sent = 0
    next_burst_pause = time.time() + random.uniform(2.0, 5.0) if burst else None

    print(
        f"[sim] target={target_ip}:{target_port} duration={duration}s "
        f"rate={rate}qps domain={base_domain}"
    )
    print(
        f"[sim] label_depth={label_depth} label_size={label_size} "
        f"benign_ratio={benign_ratio} burst={burst}"
    )
    print("[sim] Ctrl+C to stop early.")

    try:
        while time.time() < end_time:
            qname, qtype, kind, is_tunnel = _next_query(
                base_domain, label_depth, label_size, benign_ratio
            )
            if is_tunnel:
                tunnel_sent += 1

            try:
                sock.sendto(_craft_query(qname, qtype), (target_ip, target_port))
                sent += 1
            except OSError as exc:
                print(f"[sim] send error: {exc}", file=sys.stderr)

            if sent % 50 == 0:
                print(
                    f"[sim] sent={sent} tunnel={tunnel_sent} "
                    f"last={kind} qname_len={len(qname)}"
                )

            _pace(interval)
            next_burst_pause = _maybe_burst_pause(next_burst_pause)
    except KeyboardInterrupt:
        print("\n[sim] interrupted")
    finally:
        sock.close()
        print(f"[sim] done. total_sent={sent} tunnel_sent={tunnel_sent}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Simulate DNS tunneling traffic for testing dns_tunnel_cli.py",
    )
    parser.add_argument(
        "--target",
        default=None,
        help="Target IP (default: auto-detect the system DNS resolver so "
             "packets cross a real adapter and a Wi-Fi/Ethernet sniffer can see them)",
    )
    parser.add_argument("--port", type=int, default=53, help="Target UDP port (default: 53)")
    parser.add_argument("--duration", type=float, default=30.0, help="Seconds to run (default: 30)")
    parser.add_argument(
        "--rate",
        type=float,
        default=50.0,
        help="Queries per second (default: 50 — sustained exfil pace)",
    )
    parser.add_argument(
        "--domain",
        default="tunnel.example.com",
        help="Base domain appended to encoded subdomains (default: tunnel.example.com)",
    )
    parser.add_argument(
        "--benign-ratio",
        type=float,
        default=0.03,
        help="Fraction of queries that look benign (default: 0.03)",
    )
    parser.add_argument(
        "--label-depth",
        type=int,
        default=3,
        help="How many random subdomain labels to stack (default: 3)",
    )
    parser.add_argument(
        "--label-size",
        type=int,
        default=55,
        help=f"Approx chars per label, capped at {MAX_LABEL_LEN} (default: 55)",
    )
    parser.add_argument(
        "--no-burst",
        action="store_true",
        help="Disable burst/lull pacing (default: bursts enabled)",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.duration <= 0 or args.rate <= 0:
        print("duration and rate must be positive", file=sys.stderr)
        return 2
    if not 0.0 <= args.benign_ratio <= 1.0:
        print("benign-ratio must be between 0 and 1", file=sys.stderr)
        return 2
    if args.label_depth < 1:
        print("label-depth must be >= 1", file=sys.stderr)
        return 2
    if not 1 <= args.label_size <= MAX_LABEL_LEN:
        print(f"label-size must be between 1 and {MAX_LABEL_LEN}", file=sys.stderr)
        return 2

    target_ip = args.target or _detect_system_dns()
    if target_ip is None:
        print(
            "[sim] could not auto-detect a system DNS resolver; "
            "pass --target <ip> explicitly (e.g. 8.8.8.8 or your gateway)",
            file=sys.stderr,
        )
        return 2
    if target_ip.startswith("127."):
        print(
            f"[sim] WARNING: target {target_ip} is loopback — packets will NOT "
            "be visible to a sniffer attached to Wi-Fi/Ethernet on Windows.",
            file=sys.stderr,
        )

    run(
        target_ip=target_ip,
        target_port=args.port,
        duration=args.duration,
        rate=args.rate,
        base_domain=args.domain,
        benign_ratio=args.benign_ratio,
        label_depth=args.label_depth,
        label_size=args.label_size,
        burst=not args.no_burst,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
