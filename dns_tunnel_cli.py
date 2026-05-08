from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Iterable

from feature_extraction import aggregate_windows, compute_features
from inference import load_model, predict
from output_formatters import format_csv, format_json, format_table
from traffic_capture import DNSPacketRecord
from traffic_capture import capture_live, read_pcap


DEFAULT_WINDOW_SIZE = 10
MODEL_PATH = Path(__file__).with_name("dns_tunnel_classifier.joblib")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="DNS tunnel classifier CLI")
    source_group = parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument("--interface", help="Network interface for live capture")
    source_group.add_argument("--pcap", help="Path to a pcap file")
    parser.add_argument(
        "--duration",
        type=int,
        default=10,
        help="Live capture duration in seconds (default: 10)",
    )
    parser.add_argument("--src-ip", help="Only analyze traffic for a specific client IP")
    parser.add_argument(
        "--output",
        choices=["table", "json", "csv"],
        default="table",
        help="Output format (default: table)",
    )
    parser.add_argument("--output-file", help="Write formatted output to a file")
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.4,
        help="Decision threshold for TUNNEL classification (default: 0.4)",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if not 0.0 <= args.threshold <= 1.0:
        parser.error("--threshold must be between 0 and 1")
    if args.duration <= 0:
        parser.error("--duration must be greater than 0")

    model, feature_names = load_model(str(MODEL_PATH))

    if args.interface:
        mode = "live"
        results = _run_live_capture(
            interface=args.interface,
            duration=args.duration,
            src_ip=args.src_ip,
            model=model,
            feature_names=feature_names,
            threshold=args.threshold,
        )
    else:
        mode = "pcap"
        packets = read_pcap(args.pcap)
        results = _analyze_windows(
            aggregate_windows(
                packets,
                window_size=DEFAULT_WINDOW_SIZE,
                src_ip=args.src_ip,
            ),
            model=model,
            feature_names=feature_names,
            threshold=args.threshold,
        )

    metadata = {
        "mode": mode,
        "interface": args.interface if mode == "live" else None,
        "pcap": args.pcap if mode == "pcap" else None,
        "duration_sec": args.duration if mode == "live" else None,
        "threshold": args.threshold,
        "window_size_sec": DEFAULT_WINDOW_SIZE,
    }

    if args.output == "json":
        output = format_json(results, metadata)
    elif args.output == "csv":
        output = format_csv(results)
    else:
        output = format_table(results)

    if args.output_file:
        Path(args.output_file).write_text(output, encoding="utf-8")
    else:
        print(output)

    return 0


def _run_live_capture(
    interface: str,
    duration: int,
    src_ip: str | None,
    model: object,
    feature_names: list[str],
    threshold: float,
) -> list[dict[str, object]]:
    results: list[dict[str, object]] = []
    remaining = duration
    window_id = 0

    while remaining > 0:
        chunk_duration = min(DEFAULT_WINDOW_SIZE, remaining)
        packets = capture_live(interface, chunk_duration)
        windows = _group_live_window(packets, src_ip=src_ip, window_id=window_id)
        window_results = _analyze_windows(
            windows,
            model=model,
            feature_names=feature_names,
            threshold=threshold,
        )
        for result in window_results:
            if result["decision"] == "TUNNEL":
                print(_format_tunnel_alert(result), flush=True)
        results.extend(window_results)
        remaining -= chunk_duration
        window_id += 1

    return results


def _group_live_window(
    packets: Iterable[DNSPacketRecord],
    src_ip: str | None,
    window_id: int,
) -> dict[tuple[str, int], list[DNSPacketRecord]]:
    grouped: dict[tuple[str, int], list[DNSPacketRecord]] = {}
    for packet in packets:
        if src_ip and packet.client_ip != src_ip:
            continue
        key = (packet.client_ip, window_id)
        grouped.setdefault(key, []).append(packet)
    return dict(sorted(grouped.items(), key=lambda item: item[0][0]))


def _analyze_windows(
    windows: dict[tuple[str, int], list[DNSPacketRecord]],
    model: object,
    feature_names: list[str],
    threshold: float,
) -> list[dict[str, object]]:
    results: list[dict[str, object]] = []
    for (src_ip, window_id), packets_in_window in windows.items():
        features = compute_features(packets_in_window, window_size=DEFAULT_WINDOW_SIZE)
        p_tunnel, p_benign, decision, base_probs = predict(
            model,
            feature_names,
            features,
            threshold=threshold,
        )
        results.append(
            {
                "src_ip": src_ip,
                "window_id": window_id,
                "num_packets": len(packets_in_window),
                "decision": decision,
                "p_tunnel": p_tunnel,
                "p_benign": p_benign,
                "base_probs": base_probs,
            }
        )
    return results


def _format_tunnel_alert(result: dict[str, object]) -> str:
    return (
        "[ALERT] "
        f"window={result['window_id']} "
        f"src_ip={result['src_ip']} "
        f"decision={result['decision']} "
        f"p_tunnel={float(result['p_tunnel']):.4f} "
        f"packets={result['num_packets']}"
    )


if __name__ == "__main__":
    sys.exit(main())
