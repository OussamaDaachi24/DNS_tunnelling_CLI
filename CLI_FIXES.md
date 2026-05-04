# CLI Tool — Feature Extraction Bug Report & Fixes

## Context

The model (`dns_tunnel_classifier.joblib`) was trained using `feature_extract.py` (in the DNS-Tunnel-Datasets repo).  
The CLI tool computes the same 36 features in `feature_extraction.py`, but several features are computed with **different semantics**, causing the CLI tool to feed different values than what the model was trained on.

This is not a crash-level bug — inference runs fine — but it degrades detection accuracy because the model sees input distributions it has never seen during training.

---

## Bug 1 — IAT in milliseconds instead of seconds (CRITICAL)

**4 features affected:** `iat_mean`, `iat_std`, `iat_min`, `iat_max`

**Training extractor** (`feature_extract.py`):
```python
iats = [sorted_ts[i+1] - sorted_ts[i] for i in range(len(sorted_ts) - 1)]
# timestamps are Unix epoch floats (seconds) → iats are in SECONDS
```

**CLI tool** (`feature_extraction.py`, line 162):
```python
return [(curr - prev) * 1000.0 for prev, curr in zip(timestamps, timestamps[1:])]
# multiplies by 1000 → iats are in MILLISECONDS
```

The model was trained on IAT in seconds. The CLI feeds milliseconds. This is a **1000× scale error** on 4 features.

**Fix** — remove `* 1000.0`:
```python
# feature_extraction.py, _inter_arrival_times_ms()
# BEFORE:
return [(curr - prev) * 1000.0 for prev, curr in zip(timestamps, timestamps[1:])]

# AFTER:
return [(curr - prev) for curr, prev in zip(timestamps[1:], timestamps)]
```
Also rename the function to `_inter_arrival_times` to avoid future confusion.

---

## Bug 2 — IAT computed from queries only, not all packets

**Same 4 features:** `iat_mean`, `iat_std`, `iat_min`, `iat_max`

**Training extractor**: computes IAT from **all packets** (queries + responses) sorted by timestamp:
```python
timestamps = [p["timestamp"] for p in window]   # all packets
sorted_ts = sorted(timestamps)
iats = [sorted_ts[i+1] - sorted_ts[i] for ...]
```

**CLI tool** (line 100):
```python
iats = _inter_arrival_times_ms(queries)   # queries only
```

Different input → different inter-arrival distribution.

**Fix** — compute IAT from all packets:
```python
# feature_extraction.py, inside compute_features()
# BEFORE:
iats = _inter_arrival_times_ms(queries)

# AFTER:
all_timestamps = sorted(packet.timestamp for packet in packets)
iats = [(curr - prev) for prev, curr in zip(all_timestamps, all_timestamps[1:])]
```

---

## Bug 3 — query_rate uses different numerator and denominator

**Training extractor**:
```python
n = len(window)               # ALL packets (queries + responses)
duration = max(ts) - min(ts)  # actual duration of this window in seconds
query_rate = n / duration if duration > 0 else float(n)
```

**CLI tool** (line 119):
```python
query_rate = _safe_divide(n_queries, rate_window)
# n_queries = queries only
# rate_window = fixed 10.0 seconds (not actual window duration)
```

Two differences: numerator is queries-only instead of all-packets, and denominator is the fixed window size instead of the actual captured duration.

**Fix**:
```python
# feature_extraction.py, inside compute_features()
# BEFORE:
"query_rate": _safe_divide(n_queries, rate_window),

# AFTER:
"query_rate": _safe_divide(n_packets, duration_sec) if duration_sec > 0 else float(n_packets),
```

---

## Bug 4 — avg_answer_count uses responses-only denominator

**Training extractor**: computes mean over **all packets** (queries have answer_count=0):
```python
"avg_answer_count": mean([p["answer_count"] for p in window])  # denominator = all packets
```

**CLI tool** (lines 109, 153):
```python
answer_counts = [packet.answer_count for packet in responses]
"avg_answer_count": _safe_mean(answer_counts)   # denominator = responses only
```

If a window has 40 queries and 40 responses with 2 answers each, training gives mean=1.0, CLI gives mean=2.0.

**Fix**:
```python
# feature_extraction.py, inside compute_features()
# BEFORE:
answer_counts = [packet.answer_count for packet in responses]
...
"avg_answer_count": _safe_mean(answer_counts),

# AFTER:
answer_counts_all = [packet.answer_count for packet in packets]
...
"avg_answer_count": _safe_mean(answer_counts_all),
```

---

## Bug 5 — avg_rdata_len uses responses-only denominator

Same issue as Bug 4, same fix pattern.

**Training extractor**: divides by all packets:
```python
"avg_rdata_len": mean([p["rdata_len"] for p in window])   # denominator = all packets
```

**CLI tool** (lines 110, 154):
```python
rdata_lengths = [packet.rdata_len for packet in responses]
"avg_rdata_len": _safe_mean(rdata_lengths)   # denominator = responses only
```

**Fix**:
```python
# feature_extraction.py, inside compute_features()
# BEFORE:
rdata_lengths = [packet.rdata_len for packet in responses]
...
"avg_rdata_len": _safe_mean(rdata_lengths),

# AFTER:
rdata_lengths_all = [packet.rdata_len for packet in packets]
...
"avg_rdata_len": _safe_mean(rdata_lengths_all),
```

---

## Bug 6 — unique_subdomains excludes empty subdomains

**Training extractor**:
```python
"unique_subdomains": len(set(p["subdomain"] for p in window))
# includes "" (empty string) for domains with no subdomain (e.g., "google.com")
# → min value is 1 when all queries are base domains
```

**CLI tool** (lines 98, 121):
```python
non_empty_subdomains = [value for value in subdomains if value]
...
"unique_subdomains": float(len(set(non_empty_subdomains)))
# excludes empty string → value is 0 when all queries are base domains
```

**Fix**:
```python
# feature_extraction.py, inside compute_features()
# BEFORE:
non_empty_subdomains = [value for value in subdomains if value]
...
"unique_subdomains": float(len(set(non_empty_subdomains))),

# AFTER:
"unique_subdomains": float(len(set(subdomains))),   # include empty string like training did
# keep non_empty_subdomains for subdomain_entropy_mean (entropy of empty string is meaningless)
```

---

## Summary Table

| # | Feature(s) | Severity | Root Cause |
|---|-----------|----------|-----------|
| 1 | `iat_mean`, `iat_std`, `iat_min`, `iat_max` | **Critical** | ×1000 unit error (ms vs s) |
| 2 | `iat_mean`, `iat_std`, `iat_min`, `iat_max` | High | IAT from queries only, not all packets |
| 3 | `query_rate` | High | Wrong numerator (queries vs all) + wrong denominator (fixed vs actual) |
| 4 | `avg_answer_count` | Medium | Mean over responses only vs all packets |
| 5 | `avg_rdata_len` | Medium | Mean over responses only vs all packets |
| 6 | `unique_subdomains` | Low | Empty subdomain excluded vs included |

---

## Full Corrected `compute_features()` (drop-in replacement)

```python
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

    # FIX 1+2: IAT from ALL packets, in seconds (not ms)
    all_timestamps = sorted(packet.timestamp for packet in packets)
    iats = [(curr - prev) for prev, curr in zip(all_timestamps, all_timestamps[1:])]

    payload_lengths = [packet.payload_len for packet in packets]
    qname_lengths = [len(qname) for qname in qnames]
    label_counts = [len(_labels(qname)) for qname in qnames]
    max_label_lengths = [max((len(label) for label in _labels(qname)), default=0) for qname in qnames]
    subdomain_lengths = [len(subdomain) for subdomain in subdomains]
    full_entropies = [_string_entropy(qname) for qname in qnames]
    subdomain_entropies = [_string_entropy(subdomain) for subdomain in non_empty_subdomains]
    query_type_counts = [packet.query_type for packet in queries]

    duration_sec = max(packets[-1].timestamp - packets[0].timestamp, 0.0)

    features = {
        "n_packets": float(n_packets),
        "duration_sec": duration_sec,
        # FIX 3: all packets / actual duration
        "query_rate": _safe_divide(n_packets, duration_sec) if duration_sec > 0 else float(n_packets),
        "unique_qnames": float(len(set(qnames))),
        # FIX 6: include empty subdomain (matches training)
        "unique_subdomains": float(len(set(subdomains))),
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
        # FIX 4: divide by all packets, not just responses
        "avg_answer_count": _safe_mean([packet.answer_count for packet in packets]),
        # FIX 5: divide by all packets, not just responses
        "avg_rdata_len": _safe_mean([packet.rdata_len for packet in packets]),
        "nxdomain_frac": _safe_divide(
            sum(1 for packet in responses if packet.response_code == 3),
            n_responses,
        ),
    }

    return {name: float(features.get(name, 0.0)) for name in EXPECTED_FEATURES}
```

---

## What Does NOT Need Changing

- `EXPECTED_FEATURES` list — matches the model exactly (36 features, correct names)
- `SUSPICIOUS_QUERY_TYPES` — correct set
- All charset/entropy/ratio helper functions — correct implementations
- `aggregate_windows()` — correct grouping logic
- `inference.py`, `traffic_capture.py`, `output_formatters.py`, `dns_tunnel_cli.py` — no changes needed

Only `feature_extraction.py` needs to be patched.
