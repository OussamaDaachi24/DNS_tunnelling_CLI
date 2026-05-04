from __future__ import annotations

import argparse
import sys
from pathlib import Path

from feature_extraction import aggregate_windows, compute_features
from inference import load_model, predict
from output_formatters import format_csv, format_json, format_table
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
        default=0.5,
        help="Decision threshold for TUNNEL classification (default: 0.5)",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if not 0.0 <= args.threshold <= 1.0:
        parser.error("--threshold must be between 0 and 1")
    if args.duration <= 0:
        parser.error("--duration must be greater than 0")

    if args.interface:
        mode = "live"
        packets = capture_live(args.interface, args.duration)
    else:
        mode = "pcap"
        packets = read_pcap(args.pcap)

    windows = aggregate_windows(
        packets,
        window_size=DEFAULT_WINDOW_SIZE,
        src_ip=args.src_ip,
    )
    model, feature_names = load_model(str(MODEL_PATH))

    results = []
    for (src_ip, window_id), packets_in_window in windows.items():
        features = compute_features(packets_in_window, window_size=DEFAULT_WINDOW_SIZE)
        p_tunnel, p_benign, decision, base_probs = predict(
            model,
            feature_names,
            features,
            threshold=args.threshold,
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


if __name__ == "__main__":
    sys.exit(main())
