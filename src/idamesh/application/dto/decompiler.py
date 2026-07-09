"""Command/Result DTOs for ``decompile``."""

from __future__ import annotations

from dataclasses import dataclass

from idamesh.domain.entities.decompilation import Pseudocode


@dataclass(frozen=True)
class DecompileCommand:
    """Input for ``decompile``.

    ``address`` is a polymorphic selector: a hex string, a decimal string, or a
    symbol name, resolved to a function entry before decompilation.
    """

    address: str


@dataclass(frozen=True)
class DecompileResult:
    """Output for ``decompile``."""

    pseudocode: Pseudocode
