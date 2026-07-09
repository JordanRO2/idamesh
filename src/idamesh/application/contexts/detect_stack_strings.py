"""The detect_stack_strings use-case.

Runs the pure
:class:`~idamesh.domain.services.stack_strings.StackStringService` over a function's
decoded instructions — decoded through the single
:class:`~idamesh.domain.ports.instruction_decode.InstructionDecodeGateway` adapter.
When an ``address`` is given the scan is scoped to the one function that contains
it; otherwise it runs a *bounded* whole-database sweep over the function set, so a
large binary never triggers an unbounded decode.
"""

from __future__ import annotations

from typing import List, Optional

from idamesh.application.dto.detect_stack_strings import (
    MAX_SCAN_FUNCTIONS,
    MAX_STACK_STRINGS,
    DetectStackStringsCommand,
    DetectStackStringsResult,
)
from idamesh.domain.entities.function import Function
from idamesh.domain.entities.stack_string import StackString
from idamesh.domain.ports.database import DatabaseGateway
from idamesh.domain.ports.functions import FunctionRepository
from idamesh.domain.ports.instruction_decode import InstructionDecodeGateway
from idamesh.domain.services.stack_strings import StackStringService
from idamesh.domain.values.address import Selector
from idamesh.domain.values.pagination import MAX_COUNT, PageRequest

#: Ceiling on function pages walked during a whole-database sweep.
_MAX_PAGES: int = 1000


class DetectStackStringsUseCase:
    """Detect stack-assembled strings in one function or the bounded whole database.

    In single-function mode the ``address`` selector is resolved to its containing
    function, decoded, and scanned. In whole-database mode the sweep walks the
    function set page by page, decoding and scanning each up to a function and a
    match bound; a function that fails to decode is skipped rather than aborting
    the sweep. ``truncated`` is set when a bound elided further matches.
    """

    def __init__(
        self,
        decoder: InstructionDecodeGateway,
        stack_strings: StackStringService,
        functions: FunctionRepository,
        database: DatabaseGateway,
    ) -> None:
        self._decoder = decoder
        self._stack_strings = stack_strings
        self._functions = functions
        self._database = database

    def execute(
        self, command: DetectStackStringsCommand
    ) -> DetectStackStringsResult:
        """Scan the scoped function, or the bounded whole database, for stack strings."""
        if command.address.strip():
            func = self._resolve_function(command.address)
            matches = self._scan_function(func, allow_skip=False)
            return DetectStackStringsResult(
                matches=tuple(matches[:MAX_STACK_STRINGS]),
                truncated=len(matches) > MAX_STACK_STRINGS,
            )
        return self._scan_all()

    # -- internals ---------------------------------------------------------

    def _resolve_function(self, address: str) -> Function:
        """Resolve a selector to the function that contains it."""
        selector = Selector.parse(address)
        ea = self._database.resolve(selector)
        func = self._functions.get_containing(ea)
        if func is None:
            raise ValueError(f"no function contains address {ea.hex()}")
        return func

    def _scan_function(
        self, func: Function, *, allow_skip: bool
    ) -> List[StackString]:
        """Decode and scan one function; skip (return ``[]``) on decode failure in a sweep."""
        try:
            instructions = self._decoder.decode_function(func.ea)
        except Exception:  # noqa: BLE001 — swept functions decode independently
            if allow_skip:
                return []
            raise
        return self._stack_strings.detect(instructions, function=func.name)

    def _scan_all(self) -> DetectStackStringsResult:
        """Bounded whole-database sweep over the function set."""
        matches: List[StackString] = []
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
                for match in self._scan_function(func, allow_skip=True):
                    if len(matches) >= MAX_STACK_STRINGS:
                        truncated = True
                        break
                    matches.append(match)
                if len(matches) >= MAX_STACK_STRINGS:
                    truncated = True
                    break
            if truncated:
                break
            if not page.truncated and len(items) < MAX_COUNT:
                break
            offset += len(items)
            pages += 1
        return DetectStackStringsResult(matches=tuple(matches), truncated=truncated)
