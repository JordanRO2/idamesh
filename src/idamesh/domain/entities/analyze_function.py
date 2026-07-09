"""The :class:`FunctionAnalysis` entity — a composite single-function report.

``analyze_function`` bundles what an analyst would otherwise fetch tool-by-tool
into one record: the function's compact
:class:`~idamesh.domain.entities.func_profile.FuncProfile` (name, size, block and
call-degree metrics), its decompiled
:class:`~idamesh.domain.entities.decompilation.Pseudocode`, the inbound
:attr:`callers` and outbound :attr:`callees` cross-reference edges, the names of
any imported symbols it calls, and the string literals surfaced in its
pseudocode. The bundle contents are our token-economy design; the flat field
shape is what a client parses.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple

from idamesh.domain.entities.decompilation import Pseudocode
from idamesh.domain.entities.func_profile import FuncProfile
from idamesh.domain.entities.xref import Xref


@dataclass(frozen=True)
class FunctionAnalysis:
    """A composite, single-call report for one function."""

    profile: FuncProfile
    pseudocode: Pseudocode
    callers: Tuple[Xref, ...] = ()
    callees: Tuple[Xref, ...] = ()
    import_references: Tuple[str, ...] = ()
    string_literals: Tuple[str, ...] = ()
