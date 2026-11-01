from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scapy.all import DNS, DNSQR, DNSRR, IP, UDP

from dns_filter.config import AppConfig, CaptureConfig, LoggingConfig
from dns_filter.detection import Detection
from dns_filter.service import FilteringService


def make_packet(qname: str, rdata: str = "1.2.3.4"):
    return (
        IP(src="10.0.0.1", dst="8.8.8.8")
        / UDP(sport=12345, dport=53)
        / DNS(
            id=1,
            qr=1,
            qdcount=1,
            ancount=1,
            qd=DNSQR(qname=qname, qtype=1),
            an=DNSRR(rrname=qname, type=1, ttl=60, rdata=rdata),
        )
    )


class ListSink:
    def __init__(self):
        self.items: list[Detection] = []

    def emit(self, detection: Detection) -> None:
        self.items.append(detection)


class FilteringServiceTest(unittest.TestCase):
    def make_service(self):
        config = AppConfig(
            capture=CaptureConfig(),
            logging=LoggingConfig(enabled=False),
        )
        return FilteringService(config, detection_sink=ListSink())

    def test_process_packets_wires_parser_to_filter(self):
        service = self.make_service()
        try:
            stats = service.process_packets(
                [make_packet("a.example.com."), make_packet("b.example.com.")]
            )
        finally:
            service.close()

        self.assertEqual(stats.packets_received, 2)
        self.assertEqual(stats.packets_accepted, 2)
        self.assertEqual(stats.infos_extracted, 2)
        self.assertEqual(stats.filter.bucket_items, 2)
        self.assertEqual(
            sorted(info.domain for info in service.engine.burst_infos()),
            ["a.example.com.", "b.example.com."],
        )

    def test_close_is_idempotent(self):
        service = self.make_service()
        service.close()
        service.close()


if __name__ == "__main__":
    unittest.main()
