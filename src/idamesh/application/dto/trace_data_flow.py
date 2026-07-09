"""Command/Result DTOs for ``trace_data_flow``."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple

from idamesh.domain.entities.data_flow import DataFlowStep

#: Hops returned when a client omits ``max_steps``.
DEFAULT_MAX_STEPS: int = 256
#: Hard ceiling a requested ``max_steps`` is clamped to.
MAX_MAX_STEPS: int = 4096


@dataclass(frozen=True)
class TraceDataFlowCommand:
    """Input for ``trace_data_flow``.

    ``address`` (hex/decimal/symbol) fixes the anchor instruction; ``operand`` is
    the operand index on it whose value is followed; ``direction`` is ``"forward"``
    (subsequent uses/redefs) or ``"backward"`` (defining writes); ``max_steps``
    bounds the hops emitted and is clamped to a server maximum.
    """

    address: str
    operand: int = 0
    direction: str = "forward"
    max_steps: int = DEFAULT_MAX_STEPS


@dataclass(frozen=True)
class TraceDataFlowResult:
    """Output for ``trace_data_flow`` — the def-use steps the value flows through."""

    start: str
    direction: str
    steps: Tuple[DataFlowStep, ...]
    truncated: bool = False
