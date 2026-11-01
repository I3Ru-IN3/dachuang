"""Presentation helpers for DNS observations."""

from __future__ import annotations

import csv
import logging
import os
from collections.abc import Iterable

from .models import DnsInfo

logger = logging.getLogger(__name__)


def write_csv(infos: Iterable[DnsInfo], path: str | os.PathLike[str]) -> int:
    """Write *infos* to *path* as CSV and return the number of rows written."""

    rows = [info.to_mapping() for info in infos]
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=DnsInfo.CSV_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    logger.info("已保存 %s 条 DNS 记录到 %s", len(rows), path)
    return len(rows)
