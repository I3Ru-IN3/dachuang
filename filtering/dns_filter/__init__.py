"""Reusable components of the DNS filtering pipeline.

Public entry points:

``FilteringService``
    Composition root and runtime lifecycle.
``AppConfig``
    Typed, validated configuration.
``PacketGrouper``
    Size/timeout batching.
``BurstFilterEngine``
    Hot/cold filter state.
``DnsInfo``
    Normalized observation passed between layers.
"""

from __future__ import annotations

from .config import AppConfig, CaptureConfig, ConfigError, LoggingConfig
from .detection import (
    Detection,
    DetectionSink,
    Detector,
    LoggingDetectionSink,
    PayloadSizeDetector,
    PeriodicDetector,
    PrintDetectionSink,
)
from .dns_parser import (
    RECORD_TYPE_NAMES,
    extract_dns_info,
    extract_rdata_payload,
    extract_registered_domain,
    filter_dns_packets,
    is_valid_dns_packet,
    safe_get_udp_payload_size,
)
from .filters import (
    BurstFilterEngine,
    ColdFilter,
    FilterSnapshot,
    xxhash32,
)
from .grouping import GrouperStats, PacketGrouper
from .logging_setup import configure_logging
from .models import DnsInfo, FilterStats
from .service import FilteringService, ServiceStats

__all__ = [
    "AppConfig",
    "BurstFilterEngine",
    "CaptureConfig",
    "ColdFilter",
    "ConfigError",
    "Detection",
    "DetectionSink",
    "Detector",
    "DnsInfo",
    "FilterSnapshot",
    "FilterStats",
    "FilteringService",
    "GrouperStats",
    "LoggingConfig",
    "LoggingDetectionSink",
    "PacketGrouper",
    "PayloadSizeDetector",
    "PeriodicDetector",
    "PrintDetectionSink",
    "RECORD_TYPE_NAMES",
    "ServiceStats",
    "configure_logging",
    "extract_dns_info",
    "extract_rdata_payload",
    "extract_registered_domain",
    "filter_dns_packets",
    "is_valid_dns_packet",
    "safe_get_udp_payload_size",
    "xxhash32",
]
