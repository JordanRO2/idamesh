"""Command/Result DTOs for the ``declare_stack`` and ``delete_stack`` tools.

``DeclareStackCommand`` carries a polymorphic ``function`` selector plus the
variable ``name``, C ``type``, and frame ``offset``; ``DeleteStackCommand`` carries
the ``function`` selector and the variable ``name`` to remove. Their results wrap
the completed
:class:`~idamesh.domain.entities.stack_variable.StackVariableDefinition` /
:class:`~idamesh.domain.entities.stack_variable.StackVariableDeletion`. The
function selector is resolved in the use-case, which then routes the change through
the shared stack gateway.
"""

from __future__ import annotations

from dataclasses import dataclass

from idamesh.domain.entities.stack_variable import (
    StackVariableDefinition,
    StackVariableDeletion,
)


@dataclass(frozen=True)
class DeclareStackCommand:
    """Input for ``declare_stack``.

    ``function`` is a polymorphic selector resolved to the owning function's entry;
    ``name`` and ``type`` name the new frame variable and its C type; ``offset`` is
    the signed frame offset it occupies.
    """

    function: str
    name: str
    type: str
    offset: int = 0


@dataclass(frozen=True)
class DeclareStackResult:
    """Output for ``declare_stack`` — the completed frame-variable definition."""

    definition: StackVariableDefinition


@dataclass(frozen=True)
class DeleteStackCommand:
    """Input for ``delete_stack`` — the function selector and the variable name."""

    function: str
    name: str


@dataclass(frozen=True)
class DeleteStackResult:
    """Output for ``delete_stack`` — the completed frame-variable removal."""

    deletion: StackVariableDeletion
