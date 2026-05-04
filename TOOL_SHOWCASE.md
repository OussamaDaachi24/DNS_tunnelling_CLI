# DNS Tunnel CLI Showcase

This document shows what the CLI does, how its detection pipeline works, and how to use it in both supported modes:

- `pcap` mode: analyze a saved capture file
- `live` mode: sniff DNS traffic from a network interface in real time

## What The Tool Does

`dns_tunnel_cli.py` is a DNS traffic classifier. It inspects DNS packets, groups them into 10-second windows per client IP, extracts behavioral features, and sends those features to the bundled model `dns_tunnel_classifier.joblib`.

For each `(source IP, window)` pair, the tool outputs:

- the source IP
- the window number
- the number of packets seen
- the final decision: `TUNNEL` or `BENIGN`
- the ensemble probability `P(tunnel)`
- the probability from each base model: `LR`, `RF`, and `GB`

## How It Works

The pipeline is the same in both modes.

1. Capture or read packets
   - Live mode uses Scapy sniffing on a network interface.
   - Pcap mode reads packets from a `.pcap` file.

2. Normalize DNS traffic
   - Standard DNS on port `53` is supported.
   - DNS payloads on non-standard ports are also supported.
   - This is important for tunnel-like traffic that avoids the default DNS port.

3. Group packets into windows
   - Packets are grouped by client/source IP.
   - Each source is split into non-overlapping 10-second windows.

4. Extract features
   - The tool computes the 36 features expected by the bundled model.
   - These include traffic rate, uniqueness, entropy, query types, payload size, and string-shape features.

5. Run inference
   - The model returns `P(benign)` and `P(tunnel)`.
   - The tool compares `P(tunnel)` to the chosen threshold.
   - Default threshold: `0.5`

6. Format output
   - `table` for terminal use
   - `json` for automation
   - `csv` for spreadsheets or scripts

## Mode 1: PCAP Analysis

Use this mode when you already have a capture file and want to inspect it offline.

### Basic Command

```powershell
python dns_tunnel_cli.py --pcap .\capture.pcap --output table
```

### Example Commands

Table output:

```powershell
python dns_tunnel_cli.py --pcap .\capture.pcap --output table
```

JSON output:

```powershell
python dns_tunnel_cli.py --pcap .\capture.pcap --output json
```

CSV output:

```powershell
python dns_tunnel_cli.py --pcap .\capture.pcap --output csv
```

Filter to one client IP:

```powershell
python dns_tunnel_cli.py --pcap .\capture.pcap --src-ip 192.168.1.5 --output table
```

Use a stricter decision threshold:

```powershell
python dns_tunnel_cli.py --pcap .\capture.pcap --threshold 0.7 --output table
```

Write output to a file:

```powershell
python dns_tunnel_cli.py --pcap .\capture.pcap --output json --output-file .\result.json
```

### What Happens In PCAP Mode

- The tool loads all packets from the pcap.
- It keeps only traffic that can be interpreted as DNS.
- It builds 10-second windows by source IP.
- It scores each window independently.

### Example Table Output

```text
Source IP   | Window | Packets | Decision | P(tunnel) | LR     | RF     | GB
------------+--------+---------+----------+-----------+--------+--------+-------
127.0.0.1   | 0      | 20      | BENIGN   | 0.2735    | 1.0000 | 0.1816 | 0.0022
127.0.0.1   | 1      | 20      | BENIGN   | 0.2715    | 1.0000 | 0.1766 | 0.0022
```

### Example JSON Output

```json
{
  "timestamp": "2026-05-04T13:43:15.910513Z",
  "mode": "pcap",
  "interface": null,
  "pcap": "synthetic_dns.pcap",
  "duration_sec": null,
  "threshold": 0.5,
  "window_size_sec": 10,
  "windows": [
    {
      "src_ip": "192.168.1.5",
      "window_id": 0,
      "num_packets": 4,
      "decision": "BENIGN",
      "p_tunnel": 0.29352770015949536,
      "p_benign": 0.7064722998405046,
      "base_probs": {
        "lr": 1.0,
        "rf": 0.23266666666666666,
        "gb": 0.001152583732071775
      }
    }
  ]
}
```

## Mode 2: Live Capture

Use this mode when you want to watch DNS traffic in real time from a local interface.

### Basic Command

```powershell
python dns_tunnel_cli.py --interface Ethernet --duration 10 --output table
```

### Example Commands

Capture for 30 seconds:

```powershell
python dns_tunnel_cli.py --interface Ethernet --duration 30 --output table
```

Capture and export JSON:

```powershell
python dns_tunnel_cli.py --interface Ethernet --duration 20 --output json --output-file .\live_result.json
```

Watch only one client IP:

```powershell
python dns_tunnel_cli.py --interface Ethernet --duration 30 --src-ip 172.20.10.2 --output table
```

Use a stricter threshold:

```powershell
python dns_tunnel_cli.py --interface Ethernet --duration 30 --threshold 0.65 --output table
```

### What Happens In Live Mode

- Scapy starts sniffing packets from the chosen interface.
- The capture runs for the requested duration.
- The tool attempts to filter DNS traffic efficiently.
- If low-level packet filters are unavailable, it falls back to filtering in Python.
- At the end of the capture window, the tool classifies each source/window.

### Typical Live Workflow

1. Open an elevated PowerShell if your system requires admin rights for capture.
2. Start the CLI:

```powershell
python dns_tunnel_cli.py --interface Ethernet --duration 30 --output table
```

3. Generate some DNS activity from another terminal.
4. Wait for the capture to finish.
5. Review the per-window decisions.

## Interpreting The Output

The most important columns are:

- `Decision`: final class for that window
- `P(tunnel)`: final ensemble probability
- `LR`, `RF`, `GB`: probability from each base estimator
- `Packets`: number of DNS packets that contributed to that window

Interpretation tips:

- Higher `P(tunnel)` means the model sees stronger tunnel-like behavior.
- Small packet counts can make results unstable.
- One suspicious window is worth reviewing, but repeated suspicious windows from the same source are more meaningful.
- If the ensemble is mixed, inspect the source traffic more closely rather than relying on one estimator.

## Common Reasons For Empty Output

If you see `No DNS traffic detected.`, common causes are:

- the pcap contains no DNS-like packets
- you captured the wrong interface
- the live test did not generate DNS traffic during the capture window
- the pcap contains non-standard DNS traffic and you are using an older version of this tool

To verify quickly:

```powershell
python dns_tunnel_cli.py --pcap .\capture.pcap --output json
```

If `windows` is empty, the parser did not find any usable DNS records.

## Install And Run

Install dependencies:

```powershell
python -m pip install -r requirements.txt
```

Run pcap mode:

```powershell
python dns_tunnel_cli.py --pcap .\capture.pcap --output table
```

Run live mode:

```powershell
python dns_tunnel_cli.py --interface Ethernet --duration 10 --output table
```

## Important Note About The Model

The bundled `dns_tunnel_classifier.joblib` uses its own saved 36-feature schema. The CLI follows the model artifact directly so predictions remain compatible with the shipped ensemble.
