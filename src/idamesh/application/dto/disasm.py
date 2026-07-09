"""Command/Result DTOs for ``disasm``."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple

from idamesh.domain.entities.disasm import DisasmLine
from idamesh.domain.values.address import Address

#: Instructions returned when a client omits ``count``.
DEFAULT_DISASM_COUNT: int = 64
#: Hard ceiling a requested ``count`` is clamped to.
MAX_DISASM_COUNT: int = 50_000


@dataclass(frozen=True)
class DisasmCommand:
    """Input for ``disasm``.

    ``address`` is a polymorphic selector — a hex literal (``0x…``), a decimal
    literal, or a symbol name — resolved to the first instruction rendered.
    ``count`` bounds how many instructions are listed and is clamped to a server
    maximum.
    """

    address: str
    count: int = DEFAULT_DISASM_COUNT


@dataclass(frozen=True)
class DisasmResult:
    """Output for ``disasm`` — a bounded listing rooted at ``address``."""

    address: Address
    lines: Tuple[DisasmLine, ...]
    truncated: bool = False
