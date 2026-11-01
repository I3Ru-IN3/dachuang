from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import xxhash

from dns_filter.filters import BurstFilterEngine, ColdFilter, xxhash32
from dns_filter.models import DnsInfo


def make_info(domain: str, index: int = 0, **overrides) -> DnsInfo:
    values = {
        "timestamp": float(index),
        "ttl": 60,
        "payload_size": 100,
        "domain": domain,
        "registered_domain": domain,
        "record_type": 1,
        "client_ip": "10.0.0.1",
        "rdata": "1.2.3.4",
    }
    values.update(overrides)
    return DnsInfo(**values)


class ColdFilterTest(unittest.TestCase):
    def test_add_copies_batch(self):
        cold = ColdFilter()
        batch = [make_info("example.com")]
        cold.add(batch)
        batch.clear()
        self.assertEqual(len(cold), 1)
        self.assertEqual(cold.snapshot()["example.com"][0].domain, "example.com")

    def test_add_uses_first_registered_domain(self):
        cold = ColdFilter()
        cold.add([make_info("www.example.com", registered_domain="example.com")])
        self.assertIn("example.com", cold.snapshot())

    def test_clear(self):
        cold = ColdFilter()
        cold.add([make_info("example.com")])
        cold.clear()
        self.assertEqual(len(cold), 0)


class BurstFilterEngineTest(unittest.TestCase):
    def test_same_domain_appends(self):
        engine = BurstFilterEngine(bucket_count=10, hash_fn=lambda domain: 0)
        engine.add_dnsinfos([make_info("a.com"), make_info("a.com")])
        self.assertEqual(len(engine), 2)
        self.assertEqual(engine.stats().cold_items, 0)

    def test_collision_evicts_new_group_when_hash_not_divisible(self):
        # First group has two records, so 1 % 2 != 0: the new group loses.
        engine = BurstFilterEngine(bucket_count=10, hash_fn=lambda domain: 1)
        engine.add_dnsinfos([make_info("a.com"), make_info("a.com")])
        engine.add_dnsinfos([make_info("b.com")])

        self.assertEqual([info.domain for info in engine.burst_infos()], ["a.com", "a.com"])
        self.assertEqual(
            [info.domain for info in engine.cold_snapshot()["b.com"]],
            ["b.com"],
        )

    def test_collision_replaces_bucket_when_hash_divisible(self):
        # First group has one record, so 1 % 1 == 0: the old bucket is cleared.
        engine = BurstFilterEngine(bucket_count=10, hash_fn=lambda domain: 1)
        engine.add_dnsinfos([make_info("a.com")])
        engine.add_dnsinfos([make_info("b.com")])

        self.assertEqual([info.domain for info in engine.burst_infos()], ["b.com"])
        self.assertEqual(
            [info.domain for info in engine.cold_snapshot()["a.com"]],
            ["a.com"],
        )

    def test_capacity_is_a_soft_limit(self):
        engine = BurstFilterEngine(
            bucket_count=10,
            max_bucket_items=2,
            hash_fn=lambda domain: 0,
        )
        engine.add_dnsinfos([make_info("a.com"), make_info("a.com")])
        # 2 <= 2, so the whole group still enters: this is the legacy policy.
        engine.add_dnsinfos([make_info("a.com"), make_info("a.com")])
        self.assertEqual(len(engine), 4)

        # 4 > 2, so the next group is dropped.
        engine.add_dnsinfos([make_info("a.com")])
        self.assertEqual(len(engine), 4)

    def test_input_order_is_not_mutated(self):
        engine = BurstFilterEngine(bucket_count=10, hash_fn=lambda domain: 0)
        infos = [make_info("b.com"), make_info("a.com")]
        original = list(infos)
        engine.add_dnsinfos(infos)
        self.assertEqual(infos, original)

    def test_none_registered_domain_is_skipped(self):
        engine = BurstFilterEngine()
        engine.add_dnsinfos(
            [
                DnsInfo(
                    timestamp=0.0,
                    ttl=60,
                    payload_size=100,
                    domain=None,
                    registered_domain=None,
                    record_type=1,
                    client_ip="10.0.0.1",
                    rdata=None,
                )
            ]
        )
        self.assertEqual(len(engine), 0)
        self.assertEqual(engine.stats().cold_items, 0)

    def test_snapshot_values_are_immutable(self):
        engine = BurstFilterEngine(bucket_count=10, hash_fn=lambda domain: 0)
        engine.add_dnsinfos([make_info("a.com")])
        snapshot = engine.burst_snapshot()
        self.assertIsInstance(snapshot[0], tuple)

    def test_stats_and_clear(self):
        engine = BurstFilterEngine(bucket_count=10, hash_fn=lambda domain: 0)
        engine.add_dnsinfos([make_info("a.com"), make_info("a.com")])
        engine.add_dnsinfos([make_info("b.com")])

        stats = engine.stats()
        self.assertEqual(stats.bucket_count, 1)
        self.assertEqual(stats.bucket_items, 1)
        self.assertEqual(stats.cold_domain_count, 1)
        self.assertEqual(stats.cold_items, 2)

        engine.clear()
        self.assertEqual(engine.stats().bucket_items, 0)
        self.assertEqual(engine.stats().cold_items, 0)
        self.assertEqual(engine.ingest_count(0), 0)

    def test_bucket_count_and_capacity_are_separate(self):
        engine = BurstFilterEngine(bucket_count=7, max_bucket_items=3)
        self.assertEqual(engine.configured_bucket_count, 7)
        self.assertEqual(engine.max_bucket_items, 3)

    def test_injected_cold_filter_is_used_even_when_empty(self):
        cold = ColdFilter()
        engine = BurstFilterEngine(
            bucket_count=10,
            hash_fn=lambda domain: 1,
            cold_filter=cold,
        )
        engine.add_dnsinfos([make_info("a.com")])
        engine.add_dnsinfos([make_info("b.com")])

        self.assertEqual([info.domain for info in cold.snapshot()["a.com"]], ["a.com"])

    def test_invalid_configuration(self):
        with self.assertRaises(ValueError):
            BurstFilterEngine(bucket_count=0)
        with self.assertRaises(ValueError):
            BurstFilterEngine(max_bucket_items=0)

    def test_xxhash32_matches_xxhash(self):
        domain = "example.com"
        self.assertEqual(xxhash32(domain), xxhash.xxh32(domain.encode()).intdigest())


if __name__ == "__main__":
    unittest.main()
