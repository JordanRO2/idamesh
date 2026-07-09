"""The detect_vulns use-case.

Applies the pure
:class:`~idamesh.domain.services.vuln_heuristics.VulnHeuristicsService` over the
decompiled pseudocode of the functions of interest — no new adapter. When an
``address`` is given the scan is scoped to the one function that contains it;
otherwise it covers the whole database, *bounded* to the functions that actually
call a dangerous imported API (found by reusing the import/xref/danger machinery),
so a large binary never triggers an unbounded decompile sweep.
"""

from __future__ import annotations

from typing import Dict, List

from idamesh.application.dto.detect_vulns import (
    DetectVulnsCommand,
    DetectVulnsResult,
)
from idamesh.domain.entities.function import Function
from idamesh.domain.entities.vuln_finding import VulnFinding
from idamesh.domain.ports.database import DatabaseGateway
from idamesh.domain.ports.decompiler import DecompilerGateway
from idamesh.domain.ports.functions import FunctionRepository
from idamesh.domain.ports.imports import ImportRepository
from idamesh.domain.ports.xrefs import XrefRepository
from idamesh.domain.services.dangerous_apis import DangerousApiService
from idamesh.domain.services.vuln_heuristics import VulnHeuristicsService
from idamesh.domain.values.address import Selector
from idamesh.domain.values.pagination import MAX_COUNT, PageRequest

#: Ceiling on functions decompiled during a whole-database scan, so the sweep is
#: always bounded regardless of how many functions reach a dangerous API.
_MAX_FUNCTIONS: int = 200
#: Ceiling on import pages walked while collecting the dangerous-function set.
_MAX_PAGES: int = 1000


class DetectVulnsUseCase:
    """Scan one function (or the bounded whole database) for vuln heuristics.

    In single-function mode the ``address`` selector is resolved and its
    containing function decompiled and analyzed. In whole-database mode the scan
    is confined to the functions that reference a dangerous imported API — the
    ones the heuristics can say anything about — each decompiled and analyzed, up
    to a bound. A function whose decompilation fails during the whole-database
    sweep is skipped rather than aborting the scan.
    """

    def __init__(
        self,
        decompiler: DecompilerGateway,
        functions: FunctionRepository,
        xrefs: XrefRepository,
        imports: ImportRepository,
        danger: DangerousApiService,
        heuristics: VulnHeuristicsService,
        database: DatabaseGateway,
    ) -> None:
        self._decompiler = decompiler
        self._functions = functions
        self._xrefs = xrefs
        self._imports = imports
        self._danger = danger
        self._heuristics = heuristics
        self._database = database

    def execute(self, command: DetectVulnsCommand) -> DetectVulnsResult:
        """Analyze the scoped function, or the bounded whole database.

        A non-empty ``command.address`` is resolved to its containing function,
        which is decompiled and run through the heuristics. An empty address runs
        the bounded whole-database scan. An unresolvable address, an address in no
        function, or an unavailable decompiler surfaces as an error the interface
        layer renders as an ``isError`` result.
        """
        if command.address.strip():
            targets = [self._resolve_function(command.address)]
        else:
            if not self._decompiler.is_available():
                raise RuntimeError("decompiler is not available for this database")
            targets = self._dangerous_functions()

        findings: List[VulnFinding] = []
        for func in targets:
            text = self._safe_decompile(func, allow_skip=not command.address.strip())
            if text is None:
                continue
            findings.extend(
                self._heuristics.analyze(
                    address=func.ea,
                    function=func.name,
                    pseudocode=text,
                    danger=self._danger,
                )
            )
        return DetectVulnsResult(findings=tuple(findings))

    # -- internals ---------------------------------------------------------

    def _resolve_function(self, address: str) -> Function:
        """Resolve a selector to the function that contains it."""
        selector = Selector.parse(address)
        ea = self._database.resolve(selector)
        func = self._functions.get_containing(ea)
        if func is None:
            raise ValueError(f"no function contains address {ea.hex()}")
        return func

    def _safe_decompile(self, func: Function, *, allow_skip: bool):
        """Decompile ``func`` to text; skip (return ``None``) on failure in a sweep.

        In single-function mode (``allow_skip`` false) a decompiler failure
        propagates as an error. In the whole-database sweep it is swallowed so one
        stubborn function cannot abort the scan.
        """
        try:
            return self._decompiler.decompile(func.ea).text
        except Exception:  # noqa: BLE001 — swept functions fail independently
            if allow_skip:
                return None
            raise

    def _dangerous_functions(self) -> List[Function]:
        """Collect, bounded, the functions that reference a dangerous import.

        Walks the import table, and for every import that classifies as dangerous
        gathers the enclosing function of each of its call sites. The result is
        de-duplicated by function entry, preserves first-seen order, and is capped
        at :data:`_MAX_FUNCTIONS`.
        """
        found: Dict[int, Function] = {}
        offset = 0
        pages = 0
        while pages < _MAX_PAGES and len(found) < _MAX_FUNCTIONS:
            page = self._imports.list(PageRequest(offset=offset, count=MAX_COUNT))
            items = list(page.items)
            if not items:
                break
            for imported in items:
                if len(found) >= _MAX_FUNCTIONS:
                    break
                if not self._danger.is_dangerous(imported.name):
                    continue
                for ref in self._xrefs.refs_to(imported.ea):
                    if len(found) >= _MAX_FUNCTIONS:
                        break
                    func = self._functions.get_containing(ref.source)
                    if func is not None and func.ea.value not in found:
                        found[func.ea.value] = func
            if not page.truncated and len(items) < MAX_COUNT:
                break
            offset += len(items)
            pages += 1
        return list(found.values())
