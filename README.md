# DNS Tunnel Classifier CLI

`dns_tunnel_cli.py` captures DNS traffic from a live interface or a pcap file, aggregates it into 10-second windows per client IP, extracts the 36 features expected by the bundled model, and reports whether each window looks `TUNNEL` or `BENIGN`.

## Usage

Live capture:

```bash
python dns_tunnel_cli.py --interface Ethernet --duration 10 --output table
```

Pcap analysis:

```bash
python dns_tunnel_cli.py --pcap capture.pcap --output json
```

Optional flags:

```bash
python dns_tunnel_cli.py --pcap capture.pcap --src-ip 192.168.1.5 --threshold 0.65 --output csv
```

## Output Modes

- `table`: human-readable summary with per-estimator probabilities
- `json`: machine-readable payload with capture metadata and per-window results
- `csv`: flat rows for scripting or spreadsheet import

## Important Note About The Model

The implementation prompt describes one 36-feature schema, but the bundled `dns_tunnel_classifier.joblib` actually expects a different 36-feature vector:

`n_packets`, `duration_sec`, `query_rate`, `unique_qnames`, `unique_subdomains`, `unique_qname_ratio`, `iat_mean`, `iat_std`, `iat_min`, `iat_max`, `payload_mean`, `payload_std`, `payload_max`, `entropy_mean`, `entropy_std`, `subdomain_entropy_mean`, `txt_frac`, `null_frac`, `aaaa_frac`, `a_frac`, `any_frac`, `tunnel_type_frac`, `tcp_frac`, `avg_qname_len`, `avg_subdomain_len`, `avg_label_count`, `avg_max_label_len`, `avg_b64_ratio`, `avg_hex_ratio`, `avg_numeric_ratio`, `avg_consonant_ratio`, `avg_unique_char_ratio`, `n_responses`, `avg_answer_count`, `avg_rdata_len`, `nxdomain_frac`

This CLI follows the saved model artifact so inference stays compatible with the actual pickle.

## Install

```bash
python -m pip install -r requirements.txt
```

## Notes

- Live capture uses Scapy and may require administrator privileges depending on the interface and platform.
- When BPF capture filters are unavailable, the tool falls back to capturing broadly and filtering DNS packets in Python.
- Empty captures return `No DNS traffic detected.` for table output and empty collections for JSON/CSV.
