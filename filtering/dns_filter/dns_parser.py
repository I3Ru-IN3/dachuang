"""DNS packet validation and field extraction.

This module contains the pure parsing layer.  It knows about Scapy packets and
DNS record types, but nothing about filters, threads or configuration.
"""

from __future__ import annotations

import os
import socket
from collections.abc import Iterable, Sequence
from typing import Any

from scapy.all import DNS, IP, UDP, rdpcap
from scapy.packet import Packet

from .models import DnsInfo

# DNS record type numbers used by the payload decoder.
TYPE_A = 1
TYPE_NS = 2
TYPE_CNAME = 5
TYPE_SOA = 6
TYPE_PTR = 12
TYPE_MX = 15
TYPE_TXT = 16
TYPE_AAAA = 28

RECORD_TYPE_NAMES: dict[int, str] = {
    TYPE_A: "A",
    TYPE_NS: "NS",
    TYPE_CNAME: "CNAME",
    TYPE_SOA: "SOA",
    TYPE_PTR: "PTR",
    TYPE_MX: "MX",
    TYPE_TXT: "TXT",
    TYPE_AAAA: "AAAA",
}


def _decode_text(value: Any) -> str:
    """Decode DNS text without ever raising on malformed bytes."""

    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def decode_txt_rdata(rdata_bytes: bytes) -> str:
    """Decode TXT rdata stored as a sequence of length-prefixed strings."""

    result: list[str] = []
    index = 0
    while index < len(rdata_bytes):
        length = rdata_bytes[index]
        index += 1
        result.append(_decode_text(rdata_bytes[index:index + length]))
        index += length
    return " ".join(result)


def _decode_a(rr: Any, rdata: Any) -> str:
    if isinstance(rdata, bytes) and len(rdata) == 4:
        return socket.inet_ntoa(rdata)
    return str(rdata)


def _decode_aaaa(rr: Any, rdata: Any) -> str:
    if isinstance(rdata, bytes) and len(rdata) == 16:
        return socket.inet_ntop(socket.AF_INET6, rdata)
    return str(rdata)


def _decode_domain_name(rr: Any, rdata: Any) -> str:
    return _decode_text(rdata)


def _decode_mx(rr: Any, rdata: Any) -> str:
    if isinstance(rdata, bytes):
        priority = int.from_bytes(rdata[:2], byteorder="big")
        domain = _decode_text(rdata[2:])
        return f"{priority} {domain}"
    return str(rdata)


def _decode_txt(rr: Any, rdata: Any) -> str:
    strings = getattr(rr, "strings", None)
    if strings is not None:
        return " ".join(_decode_text(part) for part in strings)
    if isinstance(rdata, bytes):
        return decode_txt_rdata(rdata)
    # NOTE: Scapy exposes TXT rdata as a list.  The original implementation
    # rendered that list with ``str``; the decoding policy is intentionally
    # left unchanged by this architecture-only refactor.
    return str(rdata)


def _decode_soa(rr: Any, rdata: Any) -> str:
    if isinstance(rdata, bytes):
        return rdata.hex()
    return str(rdata)


def _decode_unknown(rr: Any, rdata: Any) -> str:
    if isinstance(rdata, bytes):
        return rdata.hex()
    return str(rdata)


# Registry-based dispatch keeps the extraction rule in one obvious place and
# makes adding a record type a one-line change.
_RDATA_DECODERS = {
    TYPE_A: _decode_a,
    TYPE_AAAA: _decode_aaaa,
    TYPE_NS: _decode_domain_name,
    TYPE_CNAME: _decode_domain_name,
    TYPE_PTR: _decode_domain_name,
    TYPE_MX: _decode_mx,
    TYPE_TXT: _decode_txt,
    TYPE_SOA: _decode_soa,
}


def extract_rdata_payload(rr: Any) -> str:
    """Extract a human-readable payload from a DNS resource record."""

    decoder = _RDATA_DECODERS.get(getattr(rr, "type", None), _decode_unknown)
    return decoder(rr, getattr(rr, "rdata", None))


def extract_registered_domain(domain: str | None) -> str | None:
    """Return the last two labels of *domain*.

    This intentionally keeps the project's original, deliberately simple
    definition.  Public-suffix handling is a policy decision for the detection
    layer and is therefore not hidden inside this helper.
    """

    if not domain:
        return None
    domain = domain.rstrip(".")
    parts = domain.split(".")
    if len(parts) < 2:
        return domain
    return ".".join(parts[-2:])


def _first_record(value: Any) -> Any | None:
    """Return the first item of a Scapy DNS section.

    Scapy represents a section with one record as a ``DNSRR``/``DNSQR`` object
    and a section with several records as a list-like object.  Normalizing that
    detail here keeps the rest of the codebase free of ``hasattr`` checks.
    """

    if value is None:
        return None
    if isinstance(value, list):
        return value[0] if value else None
    if isinstance(value, (tuple, Sequence)) and not isinstance(value, (bytes, str)):
        return value[0] if value else None
    return value


def _decode_qname(qname: Any) -> str:
    if isinstance(qname, bytes):
        return qname.decode("utf-8", errors="replace")
    return str(qname)


def is_valid_dns_packet(packet: Packet) -> bool:
    """Return whether *packet* is a DNS packet this pipeline should retain.

    A packet is retained when it has IP/UDP/DNS layers, carries at least one
    answer record, has exactly one question and has a non-empty decodable
    question name.
    """

    if not (IP in packet and UDP in packet and DNS in packet):
        return False

    dns_layer = packet[DNS]
    if not dns_layer.an:
        return False
    if not hasattr(dns_layer, "qr") or dns_layer.qdcount != 1:
        return False

    question = _first_record(dns_layer.qd)
    if question is None:
        return False

    qname = getattr(question, "qname", None)
    if isinstance(qname, bytes):
        try:
            decoded = qname.decode("utf-8")
        except UnicodeDecodeError:
            return False
    else:
        decoded = str(qname) if qname is not None else ""
    return bool(decoded)


def _read_packets(source: str | os.PathLike[str] | Iterable[Packet] | Packet) -> Iterable[Packet]:
    if isinstance(source, (str, os.PathLike)):
        return rdpcap(str(source))
    if isinstance(source, Packet):
        return [source]
    return source


def filter_dns_packets(
    source: str | os.PathLike[str] | Iterable[Packet] | Packet,
) -> list[Packet]:
    """Return all packets accepted by :func:`is_valid_dns_packet`.

    ``source`` may be a pcap path, a single packet or any iterable of packets.
    Supporting arbitrary iterables (including Scapy's ``PacketList``) keeps the
    batch and single-packet paths using the same predicate.
    """

    return [packet for packet in _read_packets(source) if is_valid_dns_packet(packet)]


def safe_get_udp_payload_size(packet: Packet) -> int:
    """Return the UDP payload length, or ``0`` if it cannot be determined."""

    try:
        if UDP in packet:
            udp_layer = packet[UDP]
            payload = getattr(udp_layer, "payload", None)
            if payload:
                return len(bytes(payload))
            load = getattr(udp_layer, "load", None)
            if load:
                return len(load)
        return 0
    except Exception:
        return 0


def extract_dns_info(
    packets: Iterable[Packet],
    output_csv: str | os.PathLike[str] | None = None,
) -> list[DnsInfo]:
    """Extract normalized DNS observations from *packets*.

    Parameters
    ----------
    packets:
        Iterable of Scapy packets.  Non-DNS packets are skipped.
    output_csv:
        Optional path.  When supplied, the observations are also written as a
        CSV file.  Without it, the function is a pure transformation.
    """

    results: list[DnsInfo] = []

    for packet in packets:
        if IP not in packet or UDP not in packet or DNS not in packet:
            continue

        dns_layer = packet[DNS]
        answer = _first_record(dns_layer.an)
        ttl = getattr(answer, "ttl", None) if answer is not None else None
        rdata = extract_rdata_payload(answer) if answer is not None else None
        payload_size = safe_get_udp_payload_size(packet)

        question = _first_record(dns_layer.qd)
        if question is not None:
            domain = _decode_qname(getattr(question, "qname", None))
            raw_type = getattr(question, "qtype", None)
            record_type = int(raw_type) if raw_type is not None else None
            registered_domain = extract_registered_domain(domain)
        else:
            domain = None
            record_type = None
            registered_domain = None

        results.append(
            DnsInfo(
                timestamp=float(packet.time),
                ttl=ttl,
                payload_size=payload_size,
                domain=domain,
                registered_domain=registered_domain,
                record_type=record_type,
                client_ip=str(packet[IP].src),
                rdata=rdata,
            )
        )

    if output_csv is not None:
        # Imported lazily to keep the parsing layer independent from output
        # formatting and to avoid a module-level import cycle.
        from .output import write_csv

        write_csv(results, output_csv)

    return results
