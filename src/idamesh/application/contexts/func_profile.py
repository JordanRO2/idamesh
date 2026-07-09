"""The ``func_profile`` use-case.

Resolves the polymorphic ``address`` selector against the database gateway, then
aggregates cheap metrics for the owning function from three existing ports — the
function repository (name/size and containment), the cross-reference repository
(caller and callee degree), and the basic-block gateway (block and edge counts) —
without invoking the decompiler.
"""

from __future__ import annotations

from idamesh.application.dto.func_profile import (
    FuncProfileCommand,
    FuncProfileResult,
)
from idamesh.domain.entities.func_profile import FuncProfile
from idamesh.domain.ports.basic_blocks import BasicBlockGateway
from idamesh.domain.ports.database import DatabaseGateway
from idamesh.domain.ports.functions import FunctionRepository
from idamesh.domain.ports.xrefs import XrefRepository
from idamesh.domain.values.address import Selector


class FuncProfileUseCase:
    """Resolve a selector and aggregate a compact profile of its function."""

    def __init__(
        self,
        functions: FunctionRepository,
        xrefs: XrefRepository,
        blocks: BasicBlockGateway,
        database: DatabaseGateway,
    ) -> None:
        self._functions = functions
        self._xrefs = xrefs
        self._blocks = blocks
        self._database = database

    def execute(self, command: FuncProfileCommand) -> FuncProfileResult:
        """Resolve ``command.address`` and assemble its function's metrics.

        The selector is resolved to a concrete address and mapped to its owning
        function. Name and size come from the function repository; caller and
        callee counts from the cross-reference repository (``refs_to`` /
        ``callees``); block and edge counts from the basic-block gateway. An
        out-of-range, unresolvable, or out-of-function address surfaces as an
        error, which the interface layer renders as an ``isError`` result.
        """
        selector = Selector.parse(command.address)
        ea = self._database.resolve(selector)
        func = self._functions.get_containing(ea)
        if func is None:
            raise LookupError(f"no function contains {ea.hex()}")

        # Anchor every metric at the function's entry point: reference counts
        # only make sense against the entry, and containment queries collapse to
        # the same function regardless of which interior address we pass.
        entry = func.ea
        blocks = self._blocks.blocks(entry)
        edge_count = sum(len(block.successors) for block in blocks)
        caller_count = len(self._xrefs.refs_to(entry))
        callee_count = len(self._xrefs.callees(entry))

        profile = FuncProfile(
            address=entry,
            name=func.name,
            size=func.size,
            block_count=len(blocks),
            edge_count=edge_count,
            caller_count=caller_count,
            callee_count=callee_count,
        )
        return FuncProfileResult(profile=profile)
