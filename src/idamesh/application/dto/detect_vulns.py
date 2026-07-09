"""Command/Result DTOs for ``detect_vulns``."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple

from idamesh.domain.entities.vuln_finding import VulnFinding


@dataclass(frozen=True)
class DetectVulnsCommand:
    """Input for ``detect_vulns``.

    ``address`` is an optional polymorphic selector — a hex literal (``0x…``), a
    decimal literal, or a symbol name — scoping the scan to the one function that
    contains it. An empty string scans the whole database (bounded to the
    functions that reach a dangerous API).
    """

    address: str = ""


@dataclass(frozen=True)
class DetectVulnsResult:
    """Output for ``detect_vulns`` — the heuristic findings raised."""

    findings: Tuple[VulnFinding, ...]
