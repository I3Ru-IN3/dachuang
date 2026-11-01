"""Application composition root.

``FilteringService`` wires the parser, grouper, filters, detectors and capture
adapter together.  It is the only place that knows about all layers; each
collaborator remains independently testable.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from scapy.all import Packet

from .capture import sniff_packets
from .config import AppConfig
from .detection import (
    DetectionSink,
    LoggingDetectionSink,
    PayloadSizeDetector,
    PeriodicDetector,
)
from .filters import BurstFilterEngine, xxhash32
from .grouping import PacketGrouper
from .models import FilterStats

logger = logging.getLogger(__name__)

DEFAULT_GROUP_SIZE = 1000
DEFAULT_GROUP_TIMEOUT = 1.0
DEFAULT_BURST_DETECT_INTERVAL = 5.0
DEFAULT_COLD_DETECT_INTERVAL = 10.0


@dataclass(frozen=True, slots=True)
class ServiceStats:
    """End-of-run counters for the CLI and for tests."""

    packets_received: int
    packets_accepted: int
    groups_flushed: int
    infos_extracted: int
    burst_detections: int
    cold_detections: int
    filter: FilterStats


class FilteringService:
    """Own the lifecycle of a single filtering run."""

    def __init__(
        self,
        config: AppConfig,
        *,
        detection_sink: DetectionSink | None = None,
        clock: Callable[[], float] = time.monotonic,
        hash_fn: Callable[[str], int] = xxhash32,
        enable_cold_detection: bool = False,
    ) -> None:
        self._config = config
        self._enable_cold_detection = enable_cold_detection

        self._engine = BurstFilterEngine(hash_fn=hash_fn)
        self._grouper = PacketGrouper(
            group_size=DEFAULT_GROUP_SIZE,
            timeout=DEFAULT_GROUP_TIMEOUT,
            callback=self._engine.add_dnsinfos,
            clock=clock,
        )

        sink = detection_sink if detection_sink is not None else LoggingDetectionSink()
        self._burst_detector = PeriodicDetector(
            interval=DEFAULT_BURST_DETECT_INTERVAL,
            snapshot=self._engine.burst_infos,
            detector=PayloadSizeDetector(),
            sink=sink,
            name="burst",
        )
        self._cold_detector = PeriodicDetector(
            interval=DEFAULT_COLD_DETECT_INTERVAL,
            snapshot=self._engine.cold_infos,
            detector=PayloadSizeDetector(),
            sink=sink,
            name="cold",
        )

        self._lifecycle_lock = threading.Lock()
        self._started = False
        self._closed = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def start(self) -> None:
        """Start background timers (idempotent)."""

        with self._lifecycle_lock:
            if self._closed:
                raise RuntimeError("服务已关闭，不能重新启动")
            if self._started:
                return
            self._grouper.start()
            self._burst_detector.start()
            if self._enable_cold_detection:
                self._cold_detector.start()
            self._started = True

    def close(self) -> None:
        """Stop timers and flush pending data (idempotent)."""

        with self._lifecycle_lock:
            if self._closed:
                return
            self._closed = True
            self._started = False

        # Flush first so the final observations are included in the summary.
        try:
            self._grouper.close()
        finally:
            self._burst_detector.stop()
            self._cold_detector.stop()

        stats = self.stats()
        logger.info(
            "运行结束: 收包 %s，通过过滤 %s，分组 %s，DNS 记录 %s，"
            "热告警 %s，冷告警 %s，热桶 %s/%s 条，冷域 %s/%s 条",
            stats.packets_received,
            stats.packets_accepted,
            stats.groups_flushed,
            stats.infos_extracted,
            stats.burst_detections,
            stats.cold_detections,
            stats.filter.bucket_count,
            stats.filter.bucket_items,
            stats.filter.cold_domain_count,
            stats.filter.cold_items,
        )

    def __enter__(self) -> "FilteringService":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Data path
    # ------------------------------------------------------------------
    def add_packet(self, packet: Packet) -> None:
        self._grouper.add(packet)

    def process_packets(self, packets: Iterable[Packet]) -> ServiceStats:
        """Process an explicit packet iterable (used by tests and scripts)."""

        for packet in packets:
            self.add_packet(packet)
        self._grouper.flush()
        return self.stats()

    def run(self) -> ServiceStats:
        """Run capture until it finishes, then return end-of-run statistics."""

        self.start()
        try:
            sniff_packets(self._config.capture, self.add_packet)
        finally:
            self.close()
        return self.stats()

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------
    def stats(self) -> ServiceStats:
        grouper = self._grouper.stats
        return ServiceStats(
            packets_received=grouper.received,
            packets_accepted=grouper.accepted,
            groups_flushed=grouper.flushed_groups,
            infos_extracted=grouper.flushed_infos,
            burst_detections=self._burst_detector.emitted,
            cold_detections=self._cold_detector.emitted,
            filter=self._engine.stats(),
        )

    @property
    def engine(self) -> BurstFilterEngine:
        return self._engine

    @property
    def grouper(self) -> PacketGrouper:
        return self._grouper
