"""Application-level limits: page sizes and the output-size threshold.

Injected into the interface layer so pagination defaults and the overflow
budget are policy, not constants scattered through the transport.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Limits:
    """Default/maximum page sizes and the structured-output byte budget."""

    default_page: int = 100
    max_page: int = 1000
    output_budget_chars: int = 50_000
