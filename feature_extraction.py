from __future__ import annotations

import math
import statistics
from collections import defaultdict
from typing import Iterable

import numpy as np

from traffic_capture import DNSPacketRecord


EXPECTED_FEATURES = [
    "n_packets",
    "duration_sec",
    "query_rate",
    "unique_qnames",
    "unique_subdomains",
    "unique_qname_ratio",
    "iat_mean",
    "iat_std",
    "iat_min",
    "iat_max",
    "payload_mean",
    "payload_std",
    "payload_max",
    "entropy_mean",
    "entropy_std",
    "subdomain_entropy_mean",
    "txt_frac",
    "null_frac",
    "aaaa_frac",
    "a_frac",
    "any_frac",
    "tunnel_type_frac",
    "tcp_frac",
    "avg_qname_len",
    "avg_subdomain_len",
    "avg_label_count",
    "avg_max_label_len",
    "avg_b64_ratio",
    "avg_hex_ratio",
    "avg_numeric_ratio",
    "avg_consonant_ratio",
    "avg_unique_char_ratio",
    "n_responses",
    "avg_answer_count",
    "avg_rdata_len",
    "nxdomain_frac",
]

SUSPICIOUS_QUERY_TYPES = {"TXT", "NULL", "ANY", "CNAME", "MX", "SRV"}
COMMON_SECOND_LEVEL_SUFFIXES = {
    "ac",
    "co",
    "com",
    "edu",
    "gov",
    "net",
    "org",
}
BASE64_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")
HEX_CHARS = set("0123456789abcdefABCDEF")
CONSONANTS = set("bcdfghjklmnpqrstvwxyz")


def aggregate_windows(
    packets: Iterable[DNSPacketRecord],
    window_size: int = 10,
    src_ip: str | None = None,
) -> dict[tuple[str, int], list[DNSPacketRecord]]:
    windows: dict[tuple[str, int], list[DNSPacketRecord]] = defaultdict(list)
    for packet in packets:
        if src_ip and packet.client_ip != src_ip:
            continue
        window_id = int(packet.timestamp // window_size) if window_size > 0 else 0
        windows[(packet.client_ip, window_id)].append(packet)
    return dict(sorted(windows.items(), key=lambda item: (item[0][0], item[0][1])))


def compute_features(
    packets_in_window: list[DNSPacketRecord],
    window_size: int = 10,
) -> dict[str, float]:
    if not packets_in_window:
        return {name: 0.0 for name in EXPECTED_FEATURES}

    packets = sorted(packets_in_window, key=lambda packet: packet.timestamp)
    queries = [packet for packet in packets if packet.is_query]
    responses = [packet for packet in packets if not packet.is_query]

    n_packets = len(packets)
    n_queries = len(queries)
    n_responses = len(responses)

    qnames = [packet.query_name for packet in queries if packet.query_name]
    subdomains = [_extract_subdomain(qname) for qname in qnames]
    non_empty_subdomains = [value for value in subdomains if value]

    iats = _inter_arrival_times_ms(queries)
    payload_lengths = [packet.payload_len for packet in packets]
    qname_lengths = [len(qname) for qname in qnames]
    label_counts = [len(_labels(qname)) for qname in qnames]
    max_label_lengths = [max((len(label) for label in _labels(qname)), default=0) for qname in qnames]
    subdomain_lengths = [len(subdomain) for subdomain in subdomains]
    full_entropies = [_string_entropy(qname) for qname in qnames]
    subdomain_entropies = [_string_entropy(subdomain) for subdomain in non_empty_subdomains]
    query_type_counts = [packet.query_type for packet in queries]
    answer_counts = [packet.answer_count for packet in responses]
    rdata_lengths = [packet.rdata_len for packet in responses]
    response_codes = [packet.response_code for packet in responses if packet.response_code is not None]

    duration_sec = max(packets[-1].timestamp - packets[0].timestamp, 0.0)
    rate_window = float(window_size) if window_size > 0 else max(duration_sec, 1.0)

    features = {
        "n_packets": float(n_packets),
        "duration_sec": duration_sec,
        "query_rate": _safe_divide(n_queries, rate_window),
        "unique_qnames": float(len(set(qnames))),
        "unique_subdomains": float(len(set(non_empty_subdomains))),
        "unique_qname_ratio": _safe_divide(len(set(qnames)), n_queries),
        "iat_mean": _safe_mean(iats),
        "iat_std": _safe_std(iats),
        "iat_min": min(iats) if iats else 0.0,
        "iat_max": max(iats) if iats else 0.0,
        "payload_mean": _safe_mean(payload_lengths),
        "payload_std": _safe_std(payload_lengths),
        "payload_max": max(payload_lengths) if payload_lengths else 0.0,
        "entropy_mean": _safe_mean(full_entropies),
        "entropy_std": _safe_std(full_entropies),
        "subdomain_entropy_mean": _safe_mean(subdomain_entropies),
        "txt_frac": _type_fraction(query_type_counts, "TXT"),
        "null_frac": _type_fraction(query_type_counts, "NULL"),
        "aaaa_frac": _type_fraction(query_type_counts, "AAAA"),
        "a_frac": _type_fraction(query_type_counts, "A"),
        "any_frac": _type_fraction(query_type_counts, "ANY"),
        "tunnel_type_frac": _safe_divide(
            sum(1 for qtype in query_type_counts if qtype in SUSPICIOUS_QUERY_TYPES),
            n_queries,
        ),
        "tcp_frac": _safe_divide(sum(1 for packet in packets if packet.transport == "TCP"), n_packets),
        "avg_qname_len": _safe_mean(qname_lengths),
        "avg_subdomain_len": _safe_mean(subdomain_lengths),
        "avg_label_count": _safe_mean(label_counts),
        "avg_max_label_len": _safe_mean(max_label_lengths),
        "avg_b64_ratio": _safe_mean([_charset_ratio(qname, BASE64_CHARS) for qname in qnames]),
        "avg_hex_ratio": _safe_mean([_charset_ratio(qname, HEX_CHARS) for qname in qnames]),
        "avg_numeric_ratio": _safe_mean([_numeric_ratio(qname) for qname in qnames]),
        "avg_consonant_ratio": _safe_mean([_consonant_ratio(qname) for qname in qnames]),
        "avg_unique_char_ratio": _safe_mean([_unique_char_ratio(qname) for qname in qnames]),
        "n_responses": float(n_responses),
        "avg_answer_count": _safe_mean(answer_counts),
        "avg_rdata_len": _safe_mean(rdata_lengths),
        "nxdomain_frac": _safe_divide(sum(1 for code in response_codes if code == 3), len(response_codes)),
    }

    return {name: float(features.get(name, 0.0)) for name in EXPECTED_FEATURES}


def _inter_arrival_times_ms(queries: list[DNSPacketRecord]) -> list[float]:
    if len(queries) < 2:
        return []
    timestamps = [packet.timestamp for packet in queries]
    return [(curr - prev) * 1000.0 for prev, curr in zip(timestamps, timestamps[1:])]


def _extract_subdomain(qname: str) -> str:
    labels = _labels(qname)
    if len(labels) <= 2:
        return ""
    base_count = _base_domain_label_count(labels)
    if len(labels) <= base_count:
        return ""
    return ".".join(labels[:-base_count])


def _base_domain_label_count(labels: list[str]) -> int:
    if len(labels) < 2:
        return len(labels)
    if (
        len(labels) >= 3
        and len(labels[-1]) == 2
        and labels[-2] in COMMON_SECOND_LEVEL_SUFFIXES
    ):
        return 3
    return 2


def _labels(qname: str) -> list[str]:
    return [label for label in qname.split(".") if label]


def _string_entropy(value: str) -> float:
    content = value.replace(".", "")
    if not content:
        return 0.0
    counts: dict[str, int] = defaultdict(int)
    for char in content:
        counts[char] += 1
    probabilities = [count / len(content) for count in counts.values()]
    return float(-sum(probability * math.log2(probability) for probability in probabilities if probability > 0))


def _charset_ratio(value: str, charset: set[str]) -> float:
    content = value.replace(".", "")
    if not content:
        return 0.0
    return sum(1 for char in content if char in charset) / len(content)


def _numeric_ratio(value: str) -> float:
    content = value.replace(".", "")
    if not content:
        return 0.0
    return sum(1 for char in content if char.isdigit()) / len(content)


def _consonant_ratio(value: str) -> float:
    content = [char.lower() for char in value.replace(".", "") if char.isalpha()]
    if not content:
        return 0.0
    return sum(1 for char in content if char in CONSONANTS) / len(content)


def _unique_char_ratio(value: str) -> float:
    content = value.replace(".", "")
    if not content:
        return 0.0
    return len(set(content)) / len(content)


def _type_fraction(query_types: list[str], name: str) -> float:
    return _safe_divide(sum(1 for qtype in query_types if qtype == name), len(query_types))


def _safe_divide(numerator: float, denominator: float) -> float:
    if not denominator:
        return 0.0
    return float(numerator) / float(denominator)


def _safe_mean(values: Iterable[float]) -> float:
    values = list(values)
    if not values:
        return 0.0
    return float(statistics.fmean(values))


def _safe_std(values: Iterable[float]) -> float:
    values = list(values)
    if len(values) < 2:
        return 0.0
    return float(np.std(values, ddof=0))
