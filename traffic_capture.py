from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
from typing import Iterable, Optional

_SCAPY_RUNTIME_ROOT = Path(__file__).resolve().parent / ".runtime"
_SCAPY_RUNTIME_ROOT.mkdir(exist_ok=True)
os.environ.setdefault("XDG_CONFIG_HOME", str(_SCAPY_RUNTIME_ROOT))
os.environ.setdefault("XDG_CACHE_HOME", str(_SCAPY_RUNTIME_ROOT))

from scapy.all import DNS, DNSQR, DNSRR, IP, IPv6, TCP, UDP, rdpcap, sniff
from scapy.error import Scapy_Exception
from scapy.layers.dns import dnsqtypes


DNS_PORT = 53


@dataclass(frozen=True)
class DNSPacketRecord:
    timestamp: float
    src_ip: str
    dst_ip: str
    client_ip: str
    transport: str
    src_port: int
    dst_port: int
    is_query: bool
    query_name: str
    query_type: str
    response_code: Optional[int]
    payload_len: int
    answer_count: int
    rdata_len: int
    flags_aa: bool
    flags_tc: bool
    flags_ra: bool


def capture_live(interface: str, duration: int) -> list[DNSPacketRecord]:
    """Capture live DNS traffic from an interface."""
    try:
        packets = sniff(
            iface=interface,
            filter="port 53",
            timeout=duration,
            store=True,
        )
    except (OSError, Scapy_Exception):
        # Some environments cannot compile or apply a BPF filter. Fall back to
        # post-filtering so the CLI still works, albeit less efficiently.
        packets = sniff(
            iface=interface,
            timeout=duration,
            store=True,
        )
    return _normalize_packets(packets)


def read_pcap(path: str) -> list[DNSPacketRecord]:
    """Read DNS traffic from a pcap file."""
    packets = rdpcap(str(Path(path)))
    return _normalize_packets(packets)


def _normalize_packets(packets: Iterable[object]) -> list[DNSPacketRecord]:
    records: list[DNSPacketRecord] = []
    first_timestamp: Optional[float] = None

    for packet in packets:
        record = _extract_record(packet)
        if record is None:
            continue
        if first_timestamp is None:
            first_timestamp = record.timestamp
        if first_timestamp is not None:
            record = DNSPacketRecord(
                timestamp=float(record.timestamp - first_timestamp),
                src_ip=record.src_ip,
                dst_ip=record.dst_ip,
                client_ip=record.client_ip,
                transport=record.transport,
                src_port=record.src_port,
                dst_port=record.dst_port,
                is_query=record.is_query,
                query_name=record.query_name,
                query_type=record.query_type,
                response_code=record.response_code,
                payload_len=record.payload_len,
                answer_count=record.answer_count,
                rdata_len=record.rdata_len,
                flags_aa=record.flags_aa,
                flags_tc=record.flags_tc,
                flags_ra=record.flags_ra,
            )
        records.append(record)

    records.sort(key=lambda record: record.timestamp)
    return records


def _extract_record(packet: object) -> Optional[DNSPacketRecord]:
    if DNS not in packet:
        return None

    dns_layer = packet[DNS]
    network_layer = packet.getlayer(IP) or packet.getlayer(IPv6)
    if network_layer is None:
        return None

    transport_layer = packet.getlayer(UDP) or packet.getlayer(TCP)
    if transport_layer is None:
        return None

    src_port = int(getattr(transport_layer, "sport", 0))
    dst_port = int(getattr(transport_layer, "dport", 0))
    if src_port != DNS_PORT and dst_port != DNS_PORT:
        return None

    src_ip = str(network_layer.src)
    dst_ip = str(network_layer.dst)
    is_query = int(getattr(dns_layer, "qr", 0)) == 0
    client_ip = src_ip if is_query else dst_ip

    query_name = _extract_qname(dns_layer)
    query_type = _extract_qtype(dns_layer)
    payload_len = len(bytes(dns_layer))
    answer_count = int(getattr(dns_layer, "ancount", 0) or 0)
    rdata_len = _response_rdata_len(dns_layer) if not is_query else 0

    return DNSPacketRecord(
        timestamp=float(getattr(packet, "time", 0.0)),
        src_ip=src_ip,
        dst_ip=dst_ip,
        client_ip=client_ip,
        transport=transport_layer.name.upper(),
        src_port=src_port,
        dst_port=dst_port,
        is_query=is_query,
        query_name=query_name,
        query_type=query_type,
        response_code=None if is_query else int(getattr(dns_layer, "rcode", 0)),
        payload_len=payload_len,
        answer_count=answer_count,
        rdata_len=rdata_len,
        flags_aa=bool(getattr(dns_layer, "aa", 0)),
        flags_tc=bool(getattr(dns_layer, "tc", 0)),
        flags_ra=bool(getattr(dns_layer, "ra", 0)),
    )


def _extract_qname(dns_layer: DNS) -> str:
    question = getattr(dns_layer, "qd", None)
    if question is None:
        return ""
    qname = getattr(question, "qname", b"")
    if isinstance(qname, bytes):
        qname = qname.decode("utf-8", errors="ignore")
    return str(qname).rstrip(".").lower()


def _extract_qtype(dns_layer: DNS) -> str:
    question = getattr(dns_layer, "qd", None)
    if question is None:
        return "UNKNOWN"
    qtype = int(getattr(question, "qtype", 0) or 0)
    return str(dnsqtypes.get(qtype, qtype)).upper()


def _response_rdata_len(dns_layer: DNS) -> int:
    answer = getattr(dns_layer, "an", None)
    count = int(getattr(dns_layer, "ancount", 0) or 0)
    if answer is None or count <= 0:
        return 0

    total = 0
    current = answer
    seen = 0
    while isinstance(current, DNSRR) and seen < count:
        rdata = getattr(current, "rdata", b"")
        if isinstance(rdata, bytes):
            total += len(rdata)
        else:
            total += len(str(rdata).encode("utf-8", errors="ignore"))
        current = getattr(current, "payload", None)
        seen += 1
    return total
