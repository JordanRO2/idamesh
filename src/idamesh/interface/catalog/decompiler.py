"""Catalog registration for ``decompile``."""

from __future__ import annotations

from idamesh.application.contexts.decompiler import DecompileUseCase
from idamesh.application.dto.decompiler import DecompileCommand
from idamesh.domain.ports.execution import MainThreadExecutor
from idamesh.interface.catalog._support import run_use_case
from idamesh.interface.catalog.views import DecompileView, decompile_view
from idamesh.interface.mcp.registry import Registry


def register_decompiler(
    registry: Registry,
    *,
    decompile_use_case: DecompileUseCase,
    executor: MainThreadExecutor,
) -> None:
    """Register ``decompile`` against the decompilation use-case."""

    @registry.tool(name="decompile")
    def decompile(address: str) -> DecompileView:
        """Return Hex-Rays pseudocode for the function at ``address``. The
        ``address`` may be a hexadecimal literal (``0x…``), a decimal literal, or
        a symbol name; it is resolved to a function entry before decompiling. The
        result carries the joined ``pseudocode`` text plus the individual source
        ``lines``. If no decompiler is available, or the address is not within a
        function, the call returns an error result rather than failing the
        protocol request."""
        command = DecompileCommand(address=address)
        result = run_use_case(executor, lambda: decompile_use_case.execute(command))
        return decompile_view(result.pseudocode)
