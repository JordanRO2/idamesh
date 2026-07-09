"""Catalog registration and wire-shape projection for ``declare_stack`` (mutating).

The ``DeclareStackView`` ``TypedDict`` gives the schema compiler an object-rooted
``outputSchema``; :func:`declare_stack_view` renders the completed definition into
that flat shape (function as ``0x`` hex, ``ok`` always true on success). The tool is
marked ``@registry.mutating`` so its advertised ``readOnlyHint`` is ``false``. The
field names mirror the interoperability contract; the projection is ours.
"""

from __future__ import annotations

from typing import TypedDict

from idamesh.application.contexts.stack import DeclareStackUseCase
from idamesh.application.dto.stack import DeclareStackCommand
from idamesh.domain.entities.stack_variable import StackVariableDefinition
from idamesh.domain.ports.execution import MainThreadExecutor
from idamesh.interface.catalog._support import run_mutation
from idamesh.interface.mcp.registry import Registry


class DeclareStackView(TypedDict):
    """The outcome of one ``declare_stack`` call."""

    function: str
    name: str
    ok: bool


def declare_stack_view(definition: StackVariableDefinition) -> DeclareStackView:
    """Project a :class:`StackVariableDefinition` into its wire shape."""
    return DeclareStackView(
        function=definition.function.hex(),
        name=definition.name,
        ok=True,
    )


def register_declare_stack(
    registry: Registry,
    *,
    declare_stack_use_case: DeclareStackUseCase,
    executor: MainThreadExecutor,
) -> None:
    """Register ``declare_stack`` against the declare-stack use-case (mutating)."""

    @registry.tool(name="declare_stack")
    @registry.mutating
    def declare_stack(
        function: str, name: str, type: str, offset: int = 0
    ) -> DeclareStackView:
        """Define a stack-frame variable on a function. The ``function`` may be a
        hexadecimal literal (``0x…``), a decimal literal, or a symbol name; it is
        resolved to the owning function's entry. ``name`` and ``type`` give the new
        frame variable its name and C type; ``offset`` is the signed frame offset it
        occupies. The result reports the resolved ``function`` (``0x`` hex), the
        variable ``name``, and ``ok``. This modifies the database. A type that will
        not parse, a variable that cannot be placed at ``offset``, or an
        unresolvable function yields an error result rather than failing the protocol
        request."""
        command = DeclareStackCommand(
            function=function, name=name, type=type, offset=offset
        )
        result = run_mutation(
            executor, lambda: declare_stack_use_case.execute(command)
        )
        return declare_stack_view(result.definition)
