"""Packet batching with size- and timeout-based flushing.

The grouper owns no filter state.  It only decides *when* a batch is ready and
hands the batch to an injected callback, which makes it straightforward to test
without sleeping or opening a network interface.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Generic, TypeVar

from .dns_parser import extract_dns_info, is_valid_dns_packet
from .models import DnsInfo

logger = logging.getLogger(__name__)

PacketT = TypeVar("PacketT")
PacketFilter = Callable[[PacketT], bool]
InfoExtractor = Callable[[Sequence[PacketT]], list[DnsInfo]]
GroupCallback = Callable[[list[DnsInfo]], None]


@dataclass(frozen=True, slots=True)
class GrouperStats:
    """Counters describing what happened to packets in the grouper."""

    received: int
    accepted: int
    flushed_groups: int
    flushed_infos: int


class PacketGrouper(Generic[PacketT]):
    """Collect packets until ``group_size`` is reached or ``timeout`` expires."""

    def __init__(
        self,
        group_size: int = 50,
        timeout: float = 1.0,
        callback: GroupCallback | None = None,
        *,
        packet_filter: PacketFilter[PacketT] = is_valid_dns_packet,
        info_extractor: InfoExtractor[PacketT] = extract_dns_info,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if group_size <= 0:
            raise ValueError("group_size must be positive")
        if timeout <= 0:
            raise ValueError("timeout must be positive")

        self._group_size = group_size
        self._timeout = timeout
        self._callback = callback
        self._packet_filter = packet_filter
        self._info_extractor = info_extractor
        self._clock = clock

        self._buffer: list[PacketT] = []
        self._lock = threading.Lock()
        self._flush_lock = threading.Lock()
        self._lifecycle_lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_flush = clock()

        self._received = 0
        self._accepted = 0
        self._flushed_groups = 0
        self._flushed_infos = 0

    # ------------------------------------------------------------------
    # Packet intake
    # ------------------------------------------------------------------
    def add(self, packet: PacketT) -> None:
        """Add one packet and flush immediately when the batch is full."""

        with self._lock:
            self._received += 1
            if not self._packet_filter(packet):
                return
            self._accepted += 1
            self._buffer.append(packet)
            batch_ready = len(self._buffer) >= self._group_size

        if batch_ready:
            self.flush()

    # ------------------------------------------------------------------
    # Flushing
    # ------------------------------------------------------------------
    def flush(self) -> list[DnsInfo]:
        """Extract and deliver the current batch.

        Flushing is serialized by ``_flush_lock`` so that the size trigger and
        the timeout trigger cannot interleave callbacks.  The buffer lock is
        released before extraction and callback execution, which keeps a slow
        consumer from blocking packet intake for longer than necessary.
        """

        with self._flush_lock:
            with self._lock:
                if not self._buffer:
                    return []
                batch = self._buffer
                self._buffer = []
                self._last_flush = self._clock()

            infos = self._info_extractor(batch)
            try:
                if infos and self._callback is not None:
                    self._callback(infos)
            finally:
                with self._lock:
                    self._flushed_groups += 1
                    self._flushed_infos += len(infos)
            return infos

    def _timeout_expired(self) -> bool:
        with self._lock:
            return bool(self._buffer) and (self._clock() - self._last_flush) >= self._timeout

    # ------------------------------------------------------------------
    # Background timeout checker
    # ------------------------------------------------------------------
    def start(self) -> None:
        """Start the background timeout checker (idempotent)."""

        with self._lifecycle_lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop.clear()
            self._thread = threading.Thread(
                target=self._timeout_loop,
                name="packet-grouper-timeout",
                daemon=True,
            )
            self._thread.start()

    # Backwards-compatible name used by the original script.
    start_timeout_checker = start

    def _timeout_loop(self) -> None:
        while not self._stop.wait(self._timeout):
            try:
                if self._timeout_expired():
                    self.flush()
            except Exception:
                logger.exception("分组超时刷新失败")

    def close(self) -> None:
        """Stop the checker and flush any remaining packets (idempotent)."""

        with self._lifecycle_lock:
            thread = self._thread
            self._thread = None
            self._stop.set()

        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=max(1.0, self._timeout * 2))

        self.flush()

    def __enter__(self) -> "PacketGrouper[PacketT]":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------
    @property
    def stats(self) -> GrouperStats:
        with self._lock:
            return GrouperStats(
                received=self._received,
                accepted=self._accepted,
                flushed_groups=self._flushed_groups,
                flushed_infos=self._flushed_infos,
            )

    @property
    def buffered_packets(self) -> int:
        with self._lock:
            return len(self._buffer)
