"""Catalog registration and wire-shape projection for ``analyze_component``.

The nested ``*View`` ``TypedDict``s give the schema compiler an object-rooted
``outputSchema``; :func:`analyze_component_view` renders the aggregated
:class:`~idamesh.domain.entities.component.Component` into that flat shape
(addresses as ``0x`` hex). The field names and the roll-up shape are ours.
"""

from __future__ import annotations

from typing import List, Optional, TypedDict

from idamesh.application.contexts.analyze_component import AnalyzeComponentUseCase
from idamesh.application.dto.analyze_component import (
    AnalyzeComponentCommand,
    AnalyzeComponentResult,
)
from idamesh.domain.entities.component import Component, ComponentMember
from idamesh.domain.ports.execution import MainThreadExecutor
from idamesh.interface.catalog._support import run_use_case
from idamesh.interface.mcp.registry import Registry


class ComponentMemberView(TypedDict):
    """One function in the component with its compact metrics."""

    address: str
    name: Optional[str]
    size: int
    caller_count: int
    callee_count: int


class AnalyzeComponentView(TypedDict):
    """A bounded call-subtree analyzed as a single unit."""

    root: str
    depth: int
    member_count: int
    total_size: int
    internal_call_count: int
    external_call_count: int
    truncated: bool
    members: List[ComponentMemberView]


def _member_view(member: ComponentMember) -> ComponentMemberView:
    return ComponentMemberView(
        address=member.address.hex(),
        name=member.name,
        size=member.size,
        caller_count=member.caller_count,
        callee_count=member.callee_count,
    )


def analyze_component_view(result: AnalyzeComponentResult) -> AnalyzeComponentView:
    """Project an ``analyze_component`` result into its wire shape."""
    component: Component = result.component
    return AnalyzeComponentView(
        root=component.root.hex(),
        depth=component.depth,
        member_count=component.member_count,
        total_size=component.total_size,
        internal_call_count=component.internal_call_count,
        external_call_count=component.external_call_count,
        truncated=component.truncated,
        members=[_member_view(member) for member in component.members],
    )


def register_analyze_component(
    registry: Registry,
    *,
    analyze_component_use_case: AnalyzeComponentUseCase,
    executor: MainThreadExecutor,
) -> None:
    """Register ``analyze_component`` against the call-subtree roll-up use-case."""

    @registry.tool(name="analyze_component")
    def analyze_component(address: str, depth: int = 2) -> AnalyzeComponentView:
        """Analyze a *component* — the call-subtree rooted at one function — as a
        single unit. The ``address`` may be a hexadecimal literal (``0x…``), a
        decimal literal, or a symbol name; it is resolved to the root function.
        ``depth`` bounds how many call layers below the root are pulled in (clamped
        to a server maximum). Each reached function is returned as a ``members``
        entry with its ``address``, ``name``, byte ``size``, and caller/callee
        degree; the component reports the aggregate ``member_count``,
        ``total_size``, and the split of call edges that stay inside the component
        (``internal_call_count``) versus leave it into imports, thunks, or
        functions past the depth bound (``external_call_count``). ``truncated`` is
        set when the depth or node bound elided further members. An out-of-range,
        unresolvable, or out-of-function root yields an error result rather than
        failing the protocol request. Read-only."""
        command = AnalyzeComponentCommand(address=address, depth=depth)
        result = run_use_case(
            executor, lambda: analyze_component_use_case.execute(command)
        )
        return analyze_component_view(result)
