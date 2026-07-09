"""The :class:`VulnFinding` entity — one heuristic vulnerability finding.

A finding records a single suspected weakness the heuristics flagged: the
``address`` it anchors to (the enclosing function's entry), the ``function`` name,
a ``kind`` naming the vulnerability class (``buffer_overflow`` / ``format_string``
/ ``command_injection`` / …), an authored ``severity`` band, and a plain-language
``description`` that names the rule that fired so the finding is explainable. The
class names are shared vocabulary (facts); the rule set, the severity model, and
every description string are our authored design.
"""

from __future__ import annotations

from dataclasses import dataclass

from idamesh.domain.values.address import Address


@dataclass(frozen=True)
class VulnFinding:
    """A single heuristic vulnerability finding, anchored to a function."""

    address: Address
    function: str | None
    kind: str
    severity: str
    description: str
