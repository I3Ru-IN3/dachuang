from __future__ import annotations

import io
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dns_filter.detection import (
    Detection,
    LoggingDetectionSink,
    PayloadSizeDetector,
    PeriodicDetector,
    PrintDetectionSink,
)
from dns_filter.models import DnsInfo


def make_info(domain: str = "example.com", payload_size: int = 100) -> DnsInfo:
    return DnsInfo(
        timestamp=0.0,
        ttl=60,
        payload_size=payload_size,
        domain=domain,
        registered_domain=domain,
        record_type=1,
        client_ip="10.0.0.1",
        rdata="1.2.3.4",
    )


class ListSink:
    def __init__(self):
        self.items: list[Detection] = []

    def emit(self, detection: Detection) -> None:
        self.items.append(detection)


class PayloadSizeDetectorTest(unittest.TestCase):
    def test_threshold_is_strict(self):
        detector = PayloadSizeDetector(threshold=100)
        infos = [make_info("small", 100), make_info("large", 101)]
        detections = list(detector.detect(infos))

        self.assertEqual(len(detections), 1)
        self.assertEqual(detections[0].info.domain, "large")
        self.assertIn("Payload Size: 101", detections[0].message)

    def test_custom_threshold(self):
        detector = PayloadSizeDetector(threshold=10)
        self.assertEqual(len(list(detector.detect([make_info(payload_size=11)]))), 1)
        self.assertEqual(len(list(detector.detect([make_info(payload_size=10)]))), 0)

    def test_invalid_threshold(self):
        with self.assertRaises(ValueError):
            PayloadSizeDetector(threshold=-1)


class PeriodicDetectorTest(unittest.TestCase):
    def test_run_once_emits_and_counts(self):
        sink = ListSink()
        runner = PeriodicDetector(
            interval=1.0,
            snapshot=lambda: [make_info("large", 101)],
            detector=PayloadSizeDetector(),
            sink=sink,
            name="test",
        )

        self.assertEqual(runner.run_once(), 1)
        self.assertEqual(runner.run_once(), 1)
        self.assertEqual(len(sink.items), 2)
        self.assertEqual(runner.emitted, 2)

    def test_invalid_interval(self):
        with self.assertRaises(ValueError):
            PeriodicDetector(
                interval=0,
                snapshot=lambda: [],
                detector=PayloadSizeDetector(),
                sink=ListSink(),
            )

    def test_stop_is_idempotent(self):
        runner = PeriodicDetector(
            interval=1.0,
            snapshot=lambda: [],
            detector=PayloadSizeDetector(),
            sink=ListSink(),
        )
        runner.stop()
        runner.stop()


class SinkTest(unittest.TestCase):
    def test_logging_sink(self):
        detection = Detection(
            rule="test",
            message="suspicious",
            info=make_info(),
        )
        sink = LoggingDetectionSink()
        with self.assertLogs("dns_filter.detection", level="WARNING") as captured:
            sink.emit(detection)
        self.assertIn("suspicious", captured.output[0])

    def test_print_sink(self):
        detection = Detection(
            rule="test",
            message="suspicious",
            info=make_info(),
        )
        output = io.StringIO()
        with redirect_stdout(output):
            PrintDetectionSink().emit(detection)
        self.assertEqual(output.getvalue().strip(), "suspicious")


if __name__ == "__main__":
    unittest.main()
