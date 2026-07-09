"""Command/Result DTOs for ``detect_stack_strings``."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple

from idamesh.domain.entities.stack_string import StackString

#: Ceiling on stack strings returned across a whole-database scan.
MAX_STACK_STRINGS: int = 2000
#: Ceiling on functions decoded during a whole-database scan (bounded sweep).
MAX_SCAN_FUNCTIONS: int = 400


@dataclass(frozen=True)
class DetectStackStringsCommand:
    """Input for ``detect_stack_strings``.

    ``address`` is an optional polymorphic selector — a hex literal (``0x…``), a
    decimal literal, or a symbol name — scoping the scan to the one function that
    contains it. An empty string runs a bounded whole-database scan.
    """

    address: str = ""


@dataclass(frozen=True)
class DetectStackStringsResult:
    """Output for ``detect_stack_strings`` — the reconstructed stack strings."""

    matches: Tuple[StackString, ...]
    truncated: bool = False
