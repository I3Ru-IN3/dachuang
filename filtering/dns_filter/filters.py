"""Hot/cold filter storage and the burst filter algorithm.

The engine is intentionally the only stateful filter component in the
pipeline.  All of its public methods are safe to call from the capture, timeout
and detection threads.  Algorithmic decisions (bucket capacity, eviction
probability) are kept in small methods so they can be changed without touching
storage or threading concerns.
"""

from __future__ import annotations

import logging
import threading
from collections import defaultdict
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from itertools import groupby

import xxhash

from .dns_parser import extract_registered_domain
from .models import DnsInfo, FilterStats

logger = logging.getLogger(__name__)

DEFAULT_BUCKET_COUNT = 100
DEFAULT_MAX_BUCKET_ITEMS = 100


def xxhash32(seed_str: str) -> int:
    """Return the 32-bit xxHash of *seed_str*."""

    return xxhash.xxh32(seed_str.encode()).intdigest()


@dataclass(frozen=True, slots=True)
class FilterSnapshot:
    """Immutable copies of both filters, suitable for analysis off-lock."""

    burst: Mapping[int, tuple[DnsInfo, ...]]
    cold: Mapping[str | None, tuple[DnsInfo, ...]]


class ColdFilter:
    """Registry of records evicted from the burst filter, keyed by domain."""

    def __init__(self, lock: threading.RLock | None = None) -> None:
        self._lock = lock or threading.RLock()
        self._items: dict[str | None, list[DnsInfo]] = defaultdict(list)

    def add(self, infos: Iterable[DnsInfo]) -> None:
        """Append a copy of *infos* under the domain of its first record."""

        batch = list(infos)
        if not batch:
            return

        first = batch[0]
        registered_domain = first.registered_domain
        if registered_domain is None:
            registered_domain = extract_registered_domain(first.domain)

        with self._lock:
            self._items[registered_domain].extend(batch)

    def snapshot(self) -> dict[str | None, tuple[DnsInfo, ...]]:
        with self._lock:
            return {domain: tuple(items) for domain, items in self._items.items()}

    def infos(self) -> list[DnsInfo]:
        with self._lock:
            return [info for items in self._items.values() for info in items]

    def clear(self) -> None:
        with self._lock:
            self._items.clear()

    def __len__(self) -> int:
        with self._lock:
            return sum(len(items) for items in self._items.values())

    @property
    def domain_count(self) -> int:
        with self._lock:
            return len(self._items)


class BurstFilterEngine:
    """Route DNS observations into hash buckets and evict collisions to cold.

    Parameters
    ----------
    bucket_count:
        Number of hash buckets.  Kept separate from per-bucket capacity.
    max_bucket_items:
        Soft per-bucket capacity.  The current algorithm allows a whole group
        to enter once the bucket has reached this size; the capacity policy is
        intentionally isolated in :meth:`_ingest_group_locked`.
    hash_fn:
        Injectable hash function, which makes bucket routing testable.
    cold_filter:
        Optional eviction sink.  By default a cold filter sharing this
        engine's lock is created.
    """

    def __init__(
        self,
        *,
        bucket_count: int = DEFAULT_BUCKET_COUNT,
        max_bucket_items: int = DEFAULT_MAX_BUCKET_ITEMS,
        hash_fn: Callable[[str], int] = xxhash32,
        cold_filter: ColdFilter | None = None,
        lock: threading.RLock | None = None,
    ) -> None:
        if bucket_count <= 0:
            raise ValueError("bucket_count must be positive")
        if max_bucket_items <= 0:
            raise ValueError("max_bucket_items must be positive")

        self._bucket_count = bucket_count
        self._max_bucket_items = max_bucket_items
        self._hash_fn = hash_fn
        self._lock = lock or threading.RLock()
        self._cold = (
            cold_filter if cold_filter is not None else ColdFilter(lock=self._lock)
        )
        self._buckets: dict[int, list[DnsInfo]] = {}
        self._ingest_counts: dict[int, int] = {}

    # ------------------------------------------------------------------
    # Ingestion
    # ------------------------------------------------------------------
    def add_dnsinfos(self, dnsinfos: Iterable[DnsInfo]) -> None:
        """Insert a batch of observations into the burst filter."""

        infos = list(dnsinfos)
        if not infos:
            return

        grouped = self._group_by_registered_domain(infos)
        with self._lock:
            for registered_domain, group in grouped:
                self._ingest_group_locked(registered_domain, group)

    @staticmethod
    def _group_by_registered_domain(infos: list[DnsInfo]) -> list[tuple[str | None, list[DnsInfo]]]:
        """Sort and group a batch, leaving the caller's list untouched."""

        ordered = sorted(
            infos,
            key=lambda item: (item.registered_domain is None, item.registered_domain or ""),
        )
        return [
            (domain, list(rows))
            for domain, rows in groupby(ordered, key=lambda item: item.registered_domain)
        ]

    def _ingest_group_locked(self, registered_domain: str | None, group: list[DnsInfo]) -> None:
        """Ingest one already-grouped batch.  The caller must hold the lock."""

        if registered_domain is None:
            logger.warning("跳过缺少注册域的 DNS 记录：%s", group[0].domain)
            return

        hash_value = self._hash_fn(registered_domain)
        index = hash_value % self._bucket_count
        bucket = self._buckets.setdefault(index, [])
        group_size = len(group)

        if not bucket:
            bucket.extend(group)
            self._ingest_counts[index] = self._ingest_counts.get(index, 0) + group_size
            return

        if registered_domain == bucket[0].registered_domain:
            # NOTE: 保持原实现的“软上限”语义：达到上限后当前整组仍进入。
            # 容量策略属于过滤算法，不在本次架构调整范围内。
            if len(bucket) <= self._max_bucket_items:
                bucket.extend(group)
                self._ingest_counts[index] = (
                    self._ingest_counts.get(index, 0) + group_size
                )
            else:
                logger.debug(
                    "热过滤器桶 %s 已满（%s 条），丢弃 %s 条 %s 记录",
                    index,
                    len(bucket),
                    group_size,
                    registered_domain,
                )
            return

        # Hash collision: choose which side survives with the legacy
        # deterministic 1/ingest_count probability.
        ingest_count = self._ingest_counts.get(index, 0)
        if ingest_count <= 0:
            logger.warning("热过滤器桶 %s 的计数异常（%s），按 1 处理", index, ingest_count)
            ingest_count = 1

        if hash_value % ingest_count == 0:
            self._cold.add(bucket)
            bucket.clear()
            bucket.extend(group)
            self._ingest_counts[index] = ingest_count + group_size
            logger.debug("热过滤器桶 %s 冲突，旧数据移入冷过滤器", index)
        else:
            self._cold.add(group)
            logger.debug("热过滤器桶 %s 冲突，新数据移入冷过滤器", index)

    # ------------------------------------------------------------------
    # Snapshots and introspection
    # ------------------------------------------------------------------
    def snapshot(self) -> FilterSnapshot:
        with self._lock:
            burst = {index: tuple(items) for index, items in self._buckets.items() if items}
            cold = self._cold.snapshot()
        return FilterSnapshot(burst=burst, cold=cold)

    def burst_snapshot(self) -> dict[int, tuple[DnsInfo, ...]]:
        """Copy the burst buckets for off-lock analysis."""

        with self._lock:
            return {index: tuple(items) for index, items in self._buckets.items() if items}

    def burst_infos(self) -> list[DnsInfo]:
        """Flatten the burst filter into a list for detection."""

        with self._lock:
            return [info for items in self._buckets.values() for info in items]

    def cold_snapshot(self) -> dict[str | None, tuple[DnsInfo, ...]]:
        with self._lock:
            return self._cold.snapshot()

    def cold_infos(self) -> list[DnsInfo]:
        with self._lock:
            return self._cold.infos()

    def stats(self) -> FilterStats:
        with self._lock:
            bucket_items = sum(len(items) for items in self._buckets.values())
            cold_items = len(self._cold)
            cold_domains = self._cold.domain_count
            return FilterStats(
                bucket_count=len(self._buckets),
                bucket_items=bucket_items,
                cold_domain_count=cold_domains,
                cold_items=cold_items,
            )

    def clear(self) -> None:
        """Remove all hot and cold state.  Primarily useful in tests."""

        with self._lock:
            self._buckets.clear()
            self._ingest_counts.clear()
            self._cold.clear()

    @property
    def configured_bucket_count(self) -> int:
        return self._bucket_count

    @property
    def max_bucket_items(self) -> int:
        return self._max_bucket_items

    def ingest_count(self, index: int) -> int:
        with self._lock:
            return self._ingest_counts.get(index, 0)

    def __len__(self) -> int:
        with self._lock:
            return sum(len(items) for items in self._buckets.values())
