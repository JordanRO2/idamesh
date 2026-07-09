"""Catalog registration and wire-shape projection for ``func_profile``.

The ``FuncProfileView`` ``TypedDict`` gives the schema compiler an object-rooted
``outputSchema``; :func:`func_profile_view` renders the aggregated metrics into
that flat shape (address as ``0x`` hex). The field names mirror the
interoperability contract; the projection is ours.
"""

from __future__ import annotations

from typing import Optional, TypedDict

from idamesh.application.contexts.func_profile import FuncProfileUseCase
from idamesh.application.dto.func_profile import (
    FuncProfileCommand,
    FuncProfileResult,
)
from idamesh.domain.ports.execution import MainThreadExecutor
from idamesh.interface.catalog._support import run_use_case
from idamesh.interface.mcp.registry import Registry


class FuncProfileView(TypedDict):
    """The compact metric summary of one function."""

    address: str
    name: Optional[str]
    size: int
    block_count: int
    edge_count: int
    caller_count: int
    callee_count: int


def func_profile_view(result: FuncProfileResult) -> FuncProfileView:
    """Project a ``func_profile`` result into its wire shape."""
    profile = result.profile
    return FuncProfileView(
        address=profile.address.hex(),
        name=profile.name,
        size=profile.size,
        block_count=profile.block_count,
        edge_count=profile.edge_count,
        caller_count=profile.caller_count,
        callee_count=profile.callee_count,
    )


def register_func_profile(
    registry: Registry,
    *,
    func_profile_use_case: FuncProfileUseCase,
    executor: MainThreadExecutor,
) -> None:
    """Register ``func_profile`` against the metric-aggregation use-case."""

    @registry.tool(name="func_profile")
    def func_profile(address: str) -> FuncProfileView:
        """Return a compact summary of the function at or containing
        ``address``, without decompiling it. The ``address`` may be a
        hexadecimal literal (``0x…``), a decimal literal, or a symbol name; it is
        resolved and mapped to its owning function first. The summary reports the
        function's ``address`` and ``name``, its byte ``size``, its control-flow
        ``block_count`` and ``edge_count``, and its call degree —
        ``caller_count`` functions reach it and ``callee_count`` functions it
        calls. An out-of-range, unresolvable, or out-of-function address yields
        an error result rather than failing the protocol request."""
        command = FuncProfileCommand(address=address)
        result = run_use_case(
            executor, lambda: func_profile_use_case.execute(command)
        )
        return func_profile_view(result)
