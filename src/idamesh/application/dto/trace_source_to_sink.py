"""Command/Result DTOs for ``trace_source_to_sink``."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple

from idamesh.domain.entities.taint import TaintPath

#: Paths returned when a client omits ``max_paths``.
DEFAULT_MAX_PATHS: int = 64
#: Hard ceiling a requested ``max_paths`` is clamped to.
MAX_MAX_PATHS: int = 512
#: Ceiling on functions decoded during a whole-database scan (bounded sweep).
MAX_SCAN_FUNCTIONS: int = 400


@dataclass(frozen=True)
class TraceSourceToSinkCommand:
    """Input for ``trace_source_to_sink``.

    ``address`` is an optional polymorphic selector scoping the scan to the one
    function that contains it; an empty string runs a bounded whole-database scan.
    ``max_paths`` bounds the source→sink paths returned and is clamped to a server
    maximum.
    """

    address: str = ""
    max_paths: int = DEFAULT_MAX_PATHS


@dataclass(frozen=True)
class TraceSourceToSinkResult:
    """Output for ``trace_source_to_sink`` — the source→sink taint paths found."""

    paths: Tuple[TaintPath, ...]
    truncated: bool = False
