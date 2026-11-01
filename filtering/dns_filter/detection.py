"""Detection policies and the periodic detection runner.

The runner knows *when* to inspect a snapshot; detectors know *what* a
suspicious observation looks like.  Keeping those two concerns separate makes
it possible to add rules without touching thread management.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Protocol

from .models import DnsInfo

logger = logging.getLogger(__name__)

DEFAULT_PAYLOAD_THRESHOLD = 100


@dataclass(frozen=True, slots=True)
class Detection:
    """One rule violation produced by a detector."""

    rule: str
    message: str
    info: DnsInfo


class Detector(Protocol):
    """A stateless (or externally synchronized) detection policy."""

    name: str

    def detect(self, infos: Iterable[DnsInfo]) -> Iterable[Detection]:
        """Yield detections for *infos*."""


class DetectionSink(Protocol):
    """Destination for detections (logging, alerting, a test list, ...)."""

    def emit(self, detection: Detection) -> None:
        """Handle one detection."""


class PayloadSizeDetector:
    """Example policy: flag DNS observations with a large UDP payload."""

    name = "payload_size"

    def __init__(self, threshold: int = DEFAULT_PAYLOAD_THRESHOLD) -> None:
        if threshold < 0:
            raise ValueError("threshold must be non-negative")
        self._threshold = threshold

    @property
    def threshold(self) -> int:
        return self._threshold

    def detect(self, infos: Iterable[DnsInfo]) -> Iterable[Detection]:
        for info in infos:
            if info.payload_size > self._threshold:
                yield Detection(
                    rule=self.name,
                    message=(
                        f"可疑流量检测到: {info.domain} "
                        f"(Payload Size: {info.payload_size} bytes)"
                    ),
                    info=info,
                )


class LoggingDetectionSink:
    """Emit detections through the standard logging system."""

    def __init__(self, logger_: logging.Logger | None = None, level: int = logging.WARNING) -> None:
        self._logger = logger_ or logger
        self._level = level

    def emit(self, detection: Detection) -> None:
        self._logger.log(self._level, "%s", detection.message)


class PrintDetectionSink:
    """Emit detections to stdout (useful for interactive runs and examples)."""

    def emit(self, detection: Detection) -> None:
        print(detection.message)


class PeriodicDetector:
    """Run a detector against a snapshot on a fixed interval.

    The snapshot callable is invoked on every tick, so the detector never holds
    the filter lock while rules execute.  This is the main reason detection can
    no longer block packet ingestion.
    """

    def __init__(
        self,
        *,
        interval: float,
        snapshot: Callable[[], Iterable[DnsInfo]],
        detector: Detector,
        sink: DetectionSink,
        name: str = "detector",
    ) -> None:
        if interval <= 0:
            raise ValueError("interval must be positive")

        self._interval = interval
        self._snapshot = snapshot
        self._detector = detector
        self._sink = sink
        self._name = name

        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lifecycle_lock = threading.Lock()
        self._run_lock = threading.Lock()
        self._emitted = 0

    @property
    def name(self) -> str:
        return self._name

    @property
    def interval(self) -> float:
        return self._interval

    def start(self) -> None:
        """Start the background loop (idempotent)."""

        with self._lifecycle_lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop.clear()
            self._thread = threading.Thread(
                target=self._loop,
                name=f"{self._name}-timer",
                daemon=True,
            )
            self._thread.start()

    def _loop(self) -> None:
        while not self._stop.wait(self._interval):
            try:
                self.run_once()
            except Exception:
                logger.exception("定时检测失败（%s）", self._name)

    def run_once(self) -> int:
        """Run one detection pass and return the number of detections."""

        with self._run_lock:
            infos = self._snapshot()
            count = 0
            for detection in self._detector.detect(infos):
                self._sink.emit(detection)
                count += 1
            self._emitted += count
            return count

    def stop(self) -> None:
        """Stop the background loop (idempotent)."""

        with self._lifecycle_lock:
            thread = self._thread
            self._thread = None
            self._stop.set()

        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=max(1.0, self._interval * 2))

    close = stop

    def __enter__(self) -> "PeriodicDetector":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()

    @property
    def emitted(self) -> int:
        return self._emitted
