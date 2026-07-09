"""The ``analyze_function`` use-case — a composite over the per-tool use-cases.

Assembles one function's report by delegating to the existing single-purpose
use-cases in one call: :class:`~idamesh.application.contexts.func_profile.FuncProfileUseCase`
for the metrics, :class:`~idamesh.application.contexts.decompiler.DecompileUseCase`
for the pseudocode, and the two cross-reference use-cases
(:class:`~idamesh.application.contexts.xrefs.XrefsToUseCase` /
:class:`~idamesh.application.contexts.xrefs.CalleesUseCase`) for the caller and
callee edges. From those it derives two cheap extras — the callee names that are
imported symbols, and the string literals surfaced in the pseudocode — without a
new port. The bundle is our token-economy design.
"""

from __future__ import annotations

import re
from typing import List, Set, Tuple

from idamesh.application.dto.analyze_function import (
    AnalyzeFunctionCommand,
    AnalyzeFunctionResult,
)
from idamesh.application.contexts.decompiler import DecompileUseCase
from idamesh.application.contexts.func_profile import FuncProfileUseCase
from idamesh.application.contexts.xrefs import CalleesUseCase, XrefsToUseCase
from idamesh.application.dto.decompiler import DecompileCommand
from idamesh.application.dto.func_profile import FuncProfileCommand
from idamesh.application.dto.xrefs import CalleesCommand, XrefsToCommand
from idamesh.domain.entities.analyze_function import FunctionAnalysis
from idamesh.domain.entities.decompilation import Pseudocode
from idamesh.domain.ports.imports import ImportRepository
from idamesh.domain.values.pagination import PageRequest

#: How many imports are pulled in to resolve import-reference names.
ANALYZE_IMPORT_SCAN: int = 1000
#: How many distinct string literals the report keeps.
ANALYZE_STRING_LITERALS: int = 32

#: Matches a double-quoted C string literal, honoring backslash escapes.
_STRING_LITERAL_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')


class AnalyzeFunctionUseCase:
    """Compose the per-tool read use-cases into one function report."""

    def __init__(
        self,
        func_profile: FuncProfileUseCase,
        decompile: DecompileUseCase,
        xrefs_to: XrefsToUseCase,
        callees: CalleesUseCase,
        imports: ImportRepository,
    ) -> None:
        self._func_profile = func_profile
        self._decompile = decompile
        self._xrefs_to = xrefs_to
        self._callees = callees
        self._imports = imports

    def execute(self, command: AnalyzeFunctionCommand) -> AnalyzeFunctionResult:
        """Resolve ``command.address`` once per sub-use-case and assemble the report.

        Each delegate resolves the polymorphic selector itself (as it does when
        called on its own), so an unresolvable or out-of-function address surfaces
        as the same error the interface layer renders as ``isError``.
        """
        address = command.address

        profile = self._func_profile.execute(
            FuncProfileCommand(address=address)
        ).profile
        pseudocode = self._decompile.execute(
            DecompileCommand(address=address)
        ).pseudocode
        callers = tuple(
            self._xrefs_to.execute(XrefsToCommand(address=address)).xrefs
        )
        callees = tuple(
            self._callees.execute(CalleesCommand(address=address)).callees
        )

        import_references = self._import_references(callees)
        string_literals = self._string_literals(pseudocode)

        analysis = FunctionAnalysis(
            profile=profile,
            pseudocode=pseudocode,
            callers=callers,
            callees=callees,
            import_references=import_references,
            string_literals=string_literals,
        )
        return AnalyzeFunctionResult(analysis=analysis)

    # -- internals --------------------------------------------------------- #

    def _import_references(self, callees: Tuple) -> Tuple[str, ...]:
        import_names = self._import_names()
        seen: Set[str] = set()
        ordered: List[str] = []
        for edge in callees:
            name = edge.target_name
            if name and name in import_names and name not in seen:
                seen.add(name)
                ordered.append(name)
        return tuple(ordered)

    def _import_names(self) -> Set[str]:
        page = self._imports.list(PageRequest.of(0, ANALYZE_IMPORT_SCAN).clamp())
        return {imp.name for imp in page.items if imp.name}

    @staticmethod
    def _string_literals(pseudocode: Pseudocode) -> Tuple[str, ...]:
        seen: Set[str] = set()
        ordered: List[str] = []
        for match in _STRING_LITERAL_RE.finditer(pseudocode.text):
            literal = match.group(1)
            if not literal or literal in seen:
                continue
            seen.add(literal)
            ordered.append(literal)
            if len(ordered) >= ANALYZE_STRING_LITERALS:
                break
        return tuple(ordered)
