from __future__ import annotations

import csv
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from scapy.all import DNS, DNSQR, DNSRR, IP, UDP
from scapy.plist import PacketList

from dns_filter.dns_parser import (
    decode_txt_rdata,
    extract_dns_info,
    extract_rdata_payload,
    extract_registered_domain,
    filter_dns_packets,
    is_valid_dns_packet,
    safe_get_udp_payload_size,
)
from support import temporary_directory


def make_packet(
    qname: str = "www.example.com.",
    qtype: int = 1,
    rdata: str = "1.2.3.4",
    ttl: int = 300,
    *,
    with_answer: bool = True,
    qr: int = 1,
):
    answer = (
        DNSRR(rrname=qname, type=qtype, ttl=ttl, rdata=rdata)
        if with_answer
        else []
    )
    return (
        IP(src="10.0.0.1", dst="8.8.8.8")
        / UDP(sport=12345, dport=53)
        / DNS(
            id=1,
            qr=qr,
            qdcount=1,
            ancount=1 if with_answer else 0,
            qd=DNSQR(qname=qname, qtype=qtype),
            an=answer,
        )
    )


class DnsParserTest(unittest.TestCase):
    def test_valid_response_packet(self):
        self.assertTrue(is_valid_dns_packet(make_packet()))

    def test_query_without_answer_is_rejected(self):
        self.assertFalse(is_valid_dns_packet(make_packet(with_answer=False)))

    def test_non_dns_packet_is_rejected(self):
        self.assertFalse(is_valid_dns_packet(IP(src="10.0.0.1") / UDP()))

    def test_multiple_questions_are_rejected(self):
        packet = make_packet()
        packet[DNS].qd = [DNSQR(qname="a.example."), DNSQR(qname="b.example.")]
        packet[DNS].qdcount = 2
        self.assertFalse(is_valid_dns_packet(packet))

    def test_zero_questions_are_rejected(self):
        packet = make_packet()
        packet[DNS].qd = []
        packet[DNS].qdcount = 0
        self.assertFalse(is_valid_dns_packet(packet))

    def test_filter_accepts_plain_list(self):
        packet = make_packet()
        self.assertEqual(filter_dns_packets([packet]), [packet])

    def test_filter_accepts_packet_list(self):
        packet = make_packet()
        self.assertEqual(filter_dns_packets(PacketList([packet])), [packet])

    def test_filter_accepts_generator(self):
        packet = make_packet()
        self.assertEqual(filter_dns_packets(iter([packet, packet])), [packet, packet])

    def test_filter_accepts_single_packet(self):
        packet = make_packet()
        self.assertEqual(filter_dns_packets(packet), [packet])

    def test_registered_domain(self):
        self.assertIsNone(extract_registered_domain(None))
        self.assertEqual(extract_registered_domain("www.example.com."), "example.com")
        self.assertEqual(extract_registered_domain("example.com"), "example.com")
        self.assertEqual(extract_registered_domain("localhost"), "localhost")
        # This project intentionally keeps the simple "last two labels" rule.
        self.assertEqual(extract_registered_domain("mail.example.co.uk"), "co.uk")

    def test_extract_dns_info(self):
        packet = make_packet(ttl=123)
        (info,) = extract_dns_info([packet])

        self.assertIsInstance(info.timestamp, float)
        self.assertEqual(info.ttl, 123)
        self.assertEqual(info.domain, "www.example.com.")
        self.assertEqual(info.registered_domain, "example.com")
        self.assertEqual(info.record_type, 1)
        self.assertEqual(info.client_ip, "10.0.0.1")
        self.assertEqual(info.rdata, "1.2.3.4")
        self.assertGreater(info.payload_size, 0)

    def test_extract_dns_info_skips_non_dns(self):
        self.assertEqual(extract_dns_info([IP(src="10.0.0.1") / UDP()]), [])

    def test_extract_txt_rdata(self):
        record = SimpleNamespace(type=16, rdata=b"\x05hello")
        self.assertEqual(extract_rdata_payload(record), "hello")

    def test_decode_txt_rdata_multiple_segments(self):
        self.assertEqual(decode_txt_rdata(b"\x03abc\x03def"), "abc def")

    def test_extract_rdata_payload_by_type(self):
        cases = [
            (DNSRR(rrname="x.", type=1, rdata="1.2.3.4"), "1.2.3.4"),
            (DNSRR(rrname="x.", type=28, rdata="2001:db8::1"), "2001:db8::1"),
            (DNSRR(rrname="x.", type=2, rdata="ns.example.com."), "ns.example.com."),
            (DNSRR(rrname="x.", type=5, rdata="alias.example.com."), "alias.example.com."),
            (DNSRR(rrname="x.", type=12, rdata="ptr.example.com."), "ptr.example.com."),
            (
                DNSRR(rrname="x.", type=15, rdata=b"\x00\x0amail.example.com."),
                "10 mail.example.com.",
            ),
            (SimpleNamespace(type=16, rdata=b"\x05hello"), "hello"),
        ]
        for record, expected in cases:
            with self.subTest(record_type=record.type):
                self.assertEqual(extract_rdata_payload(record), expected)

    def test_extract_rdata_payload_soa_is_hex(self):
        record = DNSRR(
            rrname="x.",
            type=6,
            rdata="ns.example.com. hostmaster.example.com. 1 2 3 4 5",
        )
        value = extract_rdata_payload(record)
        self.assertTrue(value)
        self.assertTrue(all(character in "0123456789abcdef" for character in value))

    def test_safe_get_udp_payload_size(self):
        self.assertGreater(safe_get_udp_payload_size(make_packet()), 0)
        self.assertEqual(safe_get_udp_payload_size(IP(src="10.0.0.1")), 0)

    def test_csv_output(self):
        packet = make_packet()
        with temporary_directory() as directory:
            path = Path(directory) / "dns.csv"
            infos = extract_dns_info([packet], output_csv=path)
            self.assertEqual(len(infos), 1)
            with path.open(newline="", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["Domain"], "www.example.com.")
            self.assertEqual(rows[0]["Registered_Domain"], "example.com")
            self.assertEqual(rows[0]["RData"], "1.2.3.4")
            self.assertIn("Client_IP", rows[0])


if __name__ == "__main__":
    unittest.main()
