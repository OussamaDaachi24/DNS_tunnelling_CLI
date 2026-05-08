from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from typing import Any


def format_table(results: list[dict[str, Any]]) -> str:
    if not results:
        return "No DNS traffic detected."

    columns = [
        ("Source IP", "src_ip"),
        ("Window", "window_id"),
        ("Packets", "num_packets"),
        ("Decision", "decision"),
        ("P(tunnel)", "p_tunnel"),
        ("LR", ("base_probs", "lr")),
        ("RF", ("base_probs", "rf")),
        ("SVM", ("base_probs", "svm")),
    ]

    rows = []
    for result in results:
        rows.append(
            [
                str(result["src_ip"]),
                str(result["window_id"]),
                str(result["num_packets"]),
                str(result["decision"]),
                f"{float(result['p_tunnel']):.4f}",
                f"{float(result['base_probs'].get('lr', 0.0)):.4f}",
                f"{float(result['base_probs'].get('rf', 0.0)):.4f}",
                f"{float(result['base_probs'].get('svm', 0.0)):.4f}",
            ]
        )

    widths = []
    headers = [column[0] for column in columns]
    for index, header in enumerate(headers):
        max_width = max(len(header), *(len(row[index]) for row in rows))
        widths.append(max_width)

    header_line = " | ".join(header.ljust(widths[index]) for index, header in enumerate(headers))
    separator_line = "-+-".join("-" * width for width in widths)
    row_lines = [
        " | ".join(value.ljust(widths[index]) for index, value in enumerate(row))
        for row in rows
    ]
    return "\n".join([header_line, separator_line, *row_lines])


def format_json(results: list[dict[str, Any]], metadata: dict[str, Any]) -> str:
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        **metadata,
        "windows": results,
    }
    return json.dumps(payload, indent=2)


def format_csv(results: list[dict[str, Any]]) -> str:
    buffer = io.StringIO()
    fieldnames = [
        "src_ip",
        "window_id",
        "num_packets",
        "decision",
        "p_tunnel",
        "p_benign",
        "lr_prob",
        "rf_prob",
        "svm_prob",
    ]
    writer = csv.DictWriter(buffer, fieldnames=fieldnames)
    writer.writeheader()
    for result in results:
        writer.writerow(
            {
                "src_ip": result["src_ip"],
                "window_id": result["window_id"],
                "num_packets": result["num_packets"],
                "decision": result["decision"],
                "p_tunnel": f"{float(result['p_tunnel']):.4f}",
                "p_benign": f"{float(result['p_benign']):.4f}",
                "lr_prob": f"{float(result['base_probs'].get('lr', 0.0)):.4f}",
                "rf_prob": f"{float(result['base_probs'].get('rf', 0.0)):.4f}",
                "svm_prob": f"{float(result['base_probs'].get('svm', 0.0)):.4f}",
            }
        )
    return buffer.getvalue()
