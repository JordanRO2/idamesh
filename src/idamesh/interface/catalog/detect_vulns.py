"""Catalog registration and wire-shape projection for ``detect_vulns``.

The ``VulnFindingView`` / ``DetectVulnsView`` ``TypedDict``s give the schema
compiler an object-rooted ``outputSchema``; :func:`detect_vulns_view` renders each
heuristic finding into that flat shape (address as ``0x`` hex). The field names
mirror the interoperability contract; the projection is ours.
"""

from __future__ import annotations

from typing import List, Optional, TypedDict

from idamesh.application.contexts.detect_vulns import DetectVulnsUseCase
from idamesh.application.dto.detect_vulns import (
    DetectVulnsCommand,
    DetectVulnsResult,
)
from idamesh.domain.entities.vuln_finding import VulnFinding
from idamesh.domain.ports.execution import MainThreadExecutor
from idamesh.interface.catalog._support import run_use_case
from idamesh.interface.mcp.registry import Registry


class VulnFindingView(TypedDict):
    """One heuristic vulnerability finding in a ``detect_vulns`` result."""

    address: str
    function: Optional[str]
    kind: str
    severity: str
    description: str


class DetectVulnsView(TypedDict):
    """The heuristic vulnerability findings raised over the scanned scope."""

    findings: List[VulnFindingView]


def vuln_finding_view(finding: VulnFinding) -> VulnFindingView:
    """Project one :class:`VulnFinding` into its wire shape (address as ``0x`` hex)."""
    return VulnFindingView(
        address=finding.address.hex(),
        function=finding.function,
        kind=finding.kind,
        severity=finding.severity,
        description=finding.description,
    )


def detect_vulns_view(result: DetectVulnsResult) -> DetectVulnsView:
    """Project a ``detect_vulns`` result into its wire shape."""
    return DetectVulnsView(
        findings=[vuln_finding_view(finding) for finding in result.findings],
    )


def register_detect_vulns(
    registry: Registry,
    *,
    detect_vulns_use_case: DetectVulnsUseCase,
    executor: MainThreadExecutor,
) -> None:
    """Register ``detect_vulns`` against the vuln-heuristics use-case."""

    @registry.tool(name="detect_vulns")
    def detect_vulns(address: str = "") -> DetectVulnsView:
        """Scan for common vulnerability patterns with explainable heuristics.

        Reads the decompiled pseudocode and applies authored rules — an unbounded
        string copy (``strcpy`` / ``gets`` / ``sprintf`` …), a ``printf``-family
        format argument that is not a literal, a ``system`` / ``exec*`` / ``popen``
        command argument that is not a literal, a ``memcpy`` whose size is not a
        constant, and dangerous APIs otherwise reachable — reporting each as a
        finding with its ``address`` (``0x`` hex, the enclosing function entry),
        the ``function`` name, a ``kind`` (``buffer_overflow`` / ``format_string``
        / ``command_injection`` / …), a ``severity`` band, and a ``description``
        that names the rule that fired. Pass an ``address`` (hex/decimal/symbol) to
        scope the scan to the one function containing it; omit it to scan the whole
        database, bounded to the functions that reach a dangerous API. An
        unresolvable address, an address in no function, or an unavailable
        decompiler yields an error result. Read-only."""
        command = DetectVulnsCommand(address=address)
        result = run_use_case(
            executor, lambda: detect_vulns_use_case.execute(command)
        )
        return detect_vulns_view(result)
