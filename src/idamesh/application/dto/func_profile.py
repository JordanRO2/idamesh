"""Command/Result DTOs for ``func_profile``.

The command carries the polymorphic ``address`` selector (resolved to a function);
the result wraps the aggregated
:class:`~idamesh.domain.entities.func_profile.FuncProfile`.
"""

from __future__ import annotations

from dataclasses import dataclass

from idamesh.domain.entities.func_profile import FuncProfile


@dataclass(frozen=True)
class FuncProfileCommand:
    """Input for ``func_profile``.

    ``address`` is a polymorphic selector — a hex literal (``0x…``), a decimal
    literal, or a symbol name — resolved to the function being profiled.
    """

    address: str


@dataclass(frozen=True)
class FuncProfileResult:
    """Output for ``func_profile`` — the compact metrics of one function."""

    profile: FuncProfile
