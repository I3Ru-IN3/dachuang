"""Shared data models for the DNS filtering pipeline.

The models in this module are deliberately dependency-free: they describe the
data that flows between the capture, parsing, filtering and detection layers.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, ClassVar, Mapping


@dataclass(frozen=True, slots=True)
class DnsInfo:
    """A normalized DNS query/response observation.

    The field names are part of the internal contract between the parser and
    the filters.  Presentation-specific names (for example the CSV header) are
    kept out of the model and live in :mod:`dns_filter.output`.
    """

    timestamp: float
    ttl: int | None
    payload_size: int
    domain: str | None
    registered_domain: str | None
    record_type: int | None
    client_ip: str
    rdata: str | None

    CSV_FIELDS: ClassVar[tuple[str, ...]] = (
        "Timestamp",
        "TTL",
        "Payload_Size",
        "Domain",
        "Registered_Domain",
        "Record_Type",
        "Client_IP",
        "RData",
    )

    def to_mapping(self) -> dict[str, Any]:
        """Return a plain dictionary using the public (CSV) field names."""

        return {
            "Timestamp": self.timestamp,
            "TTL": self.ttl,
            "Payload_Size": self.payload_size,
            "Domain": self.domain,
            "Registered_Domain": self.registered_domain,
            "Record_Type": self.record_type,
            "Client_IP": self.client_ip,
            "RData": self.rdata,
        }

    @classmethod
    def from_mapping(cls, values: Mapping[str, Any]) -> "DnsInfo":
        """Build an observation from the public field names.

        This is mostly useful for tests and for adapters that read historical
        output.  Unknown keys are ignored.
        """

        return cls(
            timestamp=float(values["Timestamp"]),
            ttl=values.get("TTL"),
            payload_size=int(values.get("Payload_Size", 0)),
            domain=values.get("Domain"),
            registered_domain=values.get("Registered_Domain"),
            record_type=values.get("Record_Type"),
            client_ip=str(values.get("Client_IP", "")),
            rdata=values.get("RData"),
        )


@dataclass(frozen=True, slots=True)
class FilterStats:
    """A point-in-time summary of the hot/cold filter contents.

    ``bucket_count`` is the number of currently non-empty hot buckets, not the
    configured bucket count.
    """

    bucket_count: int
    bucket_items: int
    cold_domain_count: int
    cold_items: int
