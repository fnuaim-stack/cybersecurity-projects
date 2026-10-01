from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class NormalizedFinding:
    asset: str
    title: str
    severity: str = "info"
    external_id: str = ""
    description: str = ""
    remediation: str = ""
    address: str = ""
    hostname: str = ""
    port: int | None = None
    protocol: str = ""
    service: str = ""
    cvss: float | None = None
    exploit_available: bool = False
    known_exploited: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


VALID_STATUSES = {
    "open",
    "in_progress",
    "resolved",
    "accepted_risk",
    "false_positive",
}
