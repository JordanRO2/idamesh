"""Command/Result DTOs for ``analyze_function``.

The command carries the polymorphic ``address`` selector (resolved to a
function); the result wraps the composite
:class:`~idamesh.domain.entities.analyze_function.FunctionAnalysis`.
"""

from __future__ import annotations

from dataclasses import dataclass

from idamesh.domain.entities.analyze_function import FunctionAnalysis


@dataclass(frozen=True)
class AnalyzeFunctionCommand:
    """Input for ``analyze_function``.

    ``address`` is a polymorphic selector — a hex literal (``0x…``), a decimal
    literal, or a symbol name — resolved to the function being analyzed.
    """

    address: str


@dataclass(frozen=True)
class AnalyzeFunctionResult:
    """Output for ``analyze_function`` — one function's composite report."""

    analysis: FunctionAnalysis
