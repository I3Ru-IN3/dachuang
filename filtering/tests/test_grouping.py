from __future__ import annotations

import sys
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dns_filter.grouping import PacketGrouper
from dns_filter.models import DnsInfo


def make_info(value: str) -> DnsInfo:
    return DnsInfo(
        timestamp=0.0,
        ttl=60,
        payload_size=10,
        domain=value,
        registered_domain=value,
        record_type=1,
        client_ip="10.0.0.1",
        rdata="1.2.3.4",
    )


def extractor(batch) -> list[DnsInfo]:
    return [make_info(str(packet)) for packet in batch]


class PacketGrouperTest(unittest.TestCase):
    def test_flushes_when_group_is_full(self):
        calls = []
        grouper = PacketGrouper(
            group_size=2,
            timeout=10.0,
            callback=calls.append,
            packet_filter=lambda packet: True,
            info_extractor=extractor,
        )

        grouper.add("a")
        self.assertEqual(calls, [])
        grouper.add("b")

        self.assertEqual(len(calls), 1)
        self.assertEqual([info.domain for info in calls[0]], ["a", "b"])
        self.assertEqual(grouper.buffered_packets, 0)

    def test_flush_delivers_partial_batch(self):
        calls = []
        grouper = PacketGrouper(
            group_size=10,
            timeout=10.0,
            callback=calls.append,
            packet_filter=lambda packet: True,
            info_extractor=extractor,
        )
        grouper.add("a")

        result = grouper.flush()
        self.assertEqual([info.domain for info in result], ["a"])
        self.assertEqual(calls, [result])
        self.assertEqual(grouper.flush(), [])

    def test_filtered_packets_are_not_buffered(self):
        grouper = PacketGrouper(
            group_size=10,
            timeout=10.0,
            packet_filter=lambda packet: packet != "bad",
            info_extractor=extractor,
        )
        grouper.add("bad")
        grouper.add("good")

        stats = grouper.stats
        self.assertEqual(stats.received, 2)
        self.assertEqual(stats.accepted, 1)
        self.assertEqual(grouper.buffered_packets, 1)

    def test_timeout_checker_flushes(self):
        flushed = threading.Event()
        grouper = PacketGrouper(
            group_size=100,
            timeout=0.02,
            callback=lambda infos: flushed.set(),
            packet_filter=lambda packet: True,
            info_extractor=extractor,
        )
        grouper.add("a")
        grouper.start()
        try:
            self.assertTrue(flushed.wait(2.0), "timeout checker did not flush")
        finally:
            grouper.close()

    def test_close_flushes_pending_packets(self):
        calls = []
        grouper = PacketGrouper(
            group_size=100,
            timeout=10.0,
            callback=calls.append,
            packet_filter=lambda packet: True,
            info_extractor=extractor,
        )
        grouper.add("a")
        grouper.close()

        self.assertEqual(len(calls), 1)
        self.assertEqual([info.domain for info in calls[0]], ["a"])

    def test_callback_exception_still_updates_stats(self):
        def callback(infos):
            raise RuntimeError("boom")

        grouper = PacketGrouper(
            group_size=1,
            timeout=10.0,
            callback=callback,
            packet_filter=lambda packet: True,
            info_extractor=extractor,
        )
        with self.assertRaises(RuntimeError):
            grouper.add("a")

        self.assertEqual(grouper.stats.flushed_groups, 1)
        self.assertEqual(grouper.stats.flushed_infos, 1)

    def test_context_manager(self):
        calls = []
        with PacketGrouper(
            group_size=100,
            timeout=10.0,
            callback=calls.append,
            packet_filter=lambda packet: True,
            info_extractor=extractor,
        ) as grouper:
            grouper.add("a")

        self.assertEqual(len(calls), 1)

    def test_invalid_arguments(self):
        with self.assertRaises(ValueError):
            PacketGrouper(group_size=0)
        with self.assertRaises(ValueError):
            PacketGrouper(timeout=0)


if __name__ == "__main__":
    unittest.main()
