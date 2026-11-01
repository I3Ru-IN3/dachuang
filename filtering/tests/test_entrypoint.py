from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import Filtering
from dns_filter.grouping import PacketGrouper


class CompatibilityEntrypointTest(unittest.TestCase):
    def test_legacy_module_exposes_main(self):
        self.assertTrue(callable(Filtering.main))

    def test_legacy_module_reexports_public_helpers(self):
        self.assertIs(Filtering.PacketGrouper, PacketGrouper)
        self.assertTrue(hasattr(Filtering, "BurstFilterEngine"))
        self.assertTrue(hasattr(Filtering, "extract_dns_info"))


if __name__ == "__main__":
    unittest.main()
