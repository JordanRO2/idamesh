"""Catalog registration and wire-shape projection for ``force_recompile`` (mutating).

The ``ForceRecompileView`` ``TypedDict`` gives the schema compiler an object-rooted
``outputSchema``; :func:`force_recompile_view` renders the completed invalidation
into that flat shape (address as ``0x`` hex, ``ok`` always true on success). The
tool is marked ``@registry.mutating`` so its advertised ``readOnlyHint`` is
``false`` — it changes decompiler cache state, though it edits no database bytes.
The field names mirror the interoperability contract; the projection is ours.
"""

from __future__ import annotations

from typing import TypedDict

from idamesh.application.contexts.force_recompile import ForceRecompileUseCase
from idamesh.application.dto.force_recompile import ForceRecompileCommand
from idamesh.domain.entities.recompilation import Recompilation
from idamesh.domain.ports.execution import MainThreadExecutor
from idamesh.interface.catalog._support import run_mutation
from idamesh.interface.mcp.registry import Registry


class ForceRecompileView(TypedDict):
    """The outcome of one ``force_recompile`` call."""

    address: str
    ok: bool


def force_recompile_view(recompilation: Recompilation) -> ForceRecompileView:
    """Project a :class:`Recompilation` into its wire shape."""
    return ForceRecompileView(
        address=recompilation.address.hex(),
        ok=True,
    )


def register_force_recompile(
    registry: Registry,
    *,
    force_recompile_use_case: ForceRecompileUseCase,
    executor: MainThreadExecutor,
) -> None:
    """Register ``force_recompile`` against the force-recompile use-case (mutating)."""

    @registry.tool(name="force_recompile")
    @registry.mutating
    def force_recompile(address: str) -> ForceRecompileView:
        """Invalidate the decompiler cache for the function at ``address``. The
        ``address`` may be a hexadecimal literal (``0x…``), a decimal literal, or a
        symbol name; it is resolved first and mapped to its enclosing function. The
        stale cached pseudocode is dropped so the next ``decompile`` regenerates
        fresh output after type, rename, operand, or data edits. The result reports
        the resolved ``address`` (``0x`` hex) and ``ok``. An address in no function,
        an unavailable decompiler, or an unresolvable address yields an error result
        rather than failing the protocol request."""
        command = ForceRecompileCommand(address=address)
        result = run_mutation(
            executor, lambda: force_recompile_use_case.execute(command)
        )
        return force_recompile_view(result.recompilation)
