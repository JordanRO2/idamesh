"""Catalog registration and wire-shape projection for ``delete_stack`` (destructive).

The ``DeleteStackView`` ``TypedDict`` gives the schema compiler an object-rooted
``outputSchema``; :func:`delete_stack_view` renders the completed removal into that
flat shape (function as ``0x`` hex, ``ok`` always true on success). The tool is
marked ``@registry.destructive`` — it discards an existing frame variable — so its
advertised ``readOnlyHint`` is ``false`` and ``destructiveHint`` is ``true``. The
field names mirror the interoperability contract; the projection is ours.
"""

from __future__ import annotations

from typing import TypedDict

from idamesh.application.contexts.stack import DeleteStackUseCase
from idamesh.application.dto.stack import DeleteStackCommand
from idamesh.domain.entities.stack_variable import StackVariableDeletion
from idamesh.domain.ports.execution import MainThreadExecutor
from idamesh.interface.catalog._support import run_mutation
from idamesh.interface.mcp.registry import Registry


class DeleteStackView(TypedDict):
    """The outcome of one ``delete_stack`` call."""

    function: str
    name: str
    ok: bool


def delete_stack_view(deletion: StackVariableDeletion) -> DeleteStackView:
    """Project a :class:`StackVariableDeletion` into its wire shape."""
    return DeleteStackView(
        function=deletion.function.hex(),
        name=deletion.name,
        ok=True,
    )


def register_delete_stack(
    registry: Registry,
    *,
    delete_stack_use_case: DeleteStackUseCase,
    executor: MainThreadExecutor,
) -> None:
    """Register ``delete_stack`` against the delete-stack use-case (destructive)."""

    @registry.tool(name="delete_stack")
    @registry.destructive
    def delete_stack(function: str, name: str) -> DeleteStackView:
        """Remove a stack-frame variable from a function. The ``function`` may be a
        hexadecimal literal (``0x…``), a decimal literal, or a symbol name; it is
        resolved to the owning function's entry. ``name`` is the frame variable to
        remove. The result reports the resolved ``function`` (``0x`` hex), the
        variable ``name``, and ``ok``. This modifies the database and destroys the
        existing frame variable. A name the frame does not carry, or an unresolvable
        function, yields an error result rather than failing the protocol
        request."""
        command = DeleteStackCommand(function=function, name=name)
        result = run_mutation(
            executor, lambda: delete_stack_use_case.execute(command)
        )
        return delete_stack_view(result.deletion)
