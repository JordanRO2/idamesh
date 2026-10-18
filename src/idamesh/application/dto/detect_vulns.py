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
    """Output for ``detect_vulns`` — the heuristic findings raised.

    ``truncated`` is set when the whole-database scan hit its function bound with
    more candidates left; ``skipped`` counts swept functions whose decompilation
    failed and were therefore not analyzed.
    """

    findings: Tuple[VulnFinding, ...]
    truncated: bool = False
    skipped: int = 0
