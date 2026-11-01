"""Packet capture adapters.

This is the only module that talks to Scapy's live/offline capture API.  The
rest of the pipeline receives packets through a callback, which keeps the
filter and detection code independent from the network stack.
"""

from __future__ import annotations

import logging
from collections.abc import Callable

from scapy.all import IFACES, Packet, sniff

from .config import CaptureConfig

logger = logging.getLogger(__name__)


class CaptureError(RuntimeError):
    """Raised when the capture source cannot be prepared."""


def resolve_interface(index: int):
    """Resolve a Scapy interface by index."""

    try:
        return IFACES.dev_from_index(index)
    except Exception as exc:  # Scapy raises different exception types per platform
        raise CaptureError(f"无法找到指定的网络接口索引 {index}: {exc}") from exc


def sniff_packets(settings: CaptureConfig, on_packet: Callable[[Packet], None]) -> None:
    """Read packets from the configured source and call *on_packet* for each."""

    settings.validate()

    timeout = None if settings.timeout <= 0 else settings.timeout
    kwargs = {
        "prn": on_packet,
        "store": 0,
        "timeout": timeout,
        "count": settings.packet_count,
    }
    if settings.bpf_filter:
        kwargs["filter"] = settings.bpf_filter

    if settings.offline_mode:
        if settings.pcap_file is None:  # already checked by validate()
            raise CaptureError("离线模式缺少 pcap 文件")
        kwargs["offline"] = str(settings.pcap_file)
        logger.info("开始离线读取: %s", settings.pcap_file)
    else:
        iface = resolve_interface(settings.interface_index)  # type: ignore[arg-type]
        kwargs["iface"] = iface
        logger.info("开始在线抓包: %s", iface)

    sniff(**kwargs)
