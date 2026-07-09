"""The trace_source_to_sink use-case.

Runs the pure :class:`~idamesh.domain.services.taint.TaintService` — which composes
the dataflow tracer and the
:class:`~idamesh.domain.services.dangerous_apis.DangerousApiService` sink set — over
a function's decoded instructions, decoded through the single
:class:`~idamesh.domain.ports.instruction_decode.InstructionDecodeGateway` adapter.
When an ``address`` is given the scan is scoped to the one containing function;
otherwise a *bounded* whole-database sweep decodes and analyzes the function set up
to a function bound.
"""

from __future__ import annotations

from typing import List

from idamesh.application.dto.trace_source_to_sink import (
    MAX_MAX_PATHS,
    MAX_SCAN_FUNCTIONS,
    TraceSourceToSinkCommand,
    TraceSourceToSinkResult,
)
from idamesh.domain.entities.function import Function
from idamesh.domain.entities.taint import TaintPath
from idamesh.domain.ports.database import DatabaseGateway
from idamesh.domain.ports.functions import FunctionRepository
from idamesh.domain.ports.instruction_decode import InstructionDecodeGateway
from idamesh.domain.services.dangerous_apis import DangerousApiService
from idamesh.domain.services.taint import TaintService
from idamesh.domain.values.address import Selector
from idamesh.domain.values.pagination import MAX_COUNT, PageRequest

#: Ceiling on function pages walked during a whole-database sweep.
_MAX_PAGES: int = 1000


class TraceSourceToSinkUseCase:
    """Find source→sink taint paths in one function or the bounded whole database.

    In single-function mode the ``address`` selector is resolved and its containing
    function decoded and analyzed. In whole-database mode the sweep walks the
    function set page by page, decoding and analyzing each up to a function and a
    path bound; a function that fails to decode is skipped rather than aborting the
    sweep. ``truncated`` is set when a bound elided further paths.
    """

    def __init__(
        self,
        decoder: InstructionDecodeGateway,
        taint: TaintService,
        functions: FunctionRepository,
        database: DatabaseGateway,
        danger: DangerousApiService,
    ) -> None:
        self._decoder = decoder
        self._taint = taint
        self._functions = functions
        self._database = database
        self._danger = danger

    def execute(
        self, command: TraceSourceToSinkCommand
    ) -> TraceSourceToSinkResult:
        """Analyze the scoped function, or the bounded whole database, for taint paths."""
        budget = min(max(command.max_paths, 0), MAX_MAX_PATHS)
        if command.address.strip():
            func = self._resolve_function(command.address)
            instructions = self._decoder.decode_function(func.ea)
            paths, truncated = self._taint.trace(
                instructions, danger=self._danger, max_paths=budget
            )
            return TraceSourceToSinkResult(paths=tuple(paths), truncated=truncated)
        return self._scan_all(budget)

    # -- internals ---------------------------------------------------------

    def _resolve_function(self, address: str) -> Function:
        """Resolve a selector to the function that contains it."""
        selector = Selector.parse(address)
        ea = self._database.resolve(selector)
        func = self._functions.get_containing(ea)
        if func is None:
            raise ValueError(f"no function contains address {ea.hex()}")
        return func

    def _scan_all(self, budget: int) -> TraceSourceToSinkResult:
        """Bounded whole-database sweep over the function set."""
        paths: List[TaintPath] = []
        truncated = False
        scanned = 0
        offset = 0
        pages = 0
        while pages < _MAX_PAGES and scanned < MAX_SCAN_FUNCTIONS:
            page = self._functions.list(PageRequest(offset=offset, count=MAX_COUNT))
            items = list(page.items)
            if not items:
                break
            for func in items:
                if scanned >= MAX_SCAN_FUNCTIONS:
                    truncated = True
                    break
                scanned += 1
                remaining = budget - len(paths)
                if remaining <= 0:
                    truncated = True
                    break
                found, func_truncated = self._analyze(func, remaining)
                paths.extend(found)
                if func_truncated:
                    truncated = True
            if truncated:
                break
            if not page.truncated and len(items) < MAX_COUNT:
                break
            offset += len(items)
            pages += 1
        return TraceSourceToSinkResult(paths=tuple(paths), truncated=truncated)

    def _analyze(self, func: Function, remaining: int):
        """Decode and analyze one function; skip on decode failure in a sweep."""
        try:
            instructions = self._decoder.decode_function(func.ea)
        except Exception:  # noqa: BLE001 — swept functions decode independently
            return [], False
        return self._taint.trace(
            instructions, danger=self._danger, max_paths=remaining
        )
