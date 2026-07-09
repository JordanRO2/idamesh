"""Command/Result DTOs for the ``define_func`` and ``undefine`` tools.

``DefineFuncCommand`` / ``UndefineCommand`` each carry a polymorphic address
selector; their results wrap the completed
:class:`~idamesh.domain.entities.code_definition.FunctionDefinition` /
:class:`~idamesh.domain.entities.code_definition.Undefinition`. The selector is
resolved in the use-case, which then routes the create/undefine through the shared
code-definition gateway.
"""

from __future__ import annotations

from dataclasses import dataclass

from idamesh.domain.entities.code_definition import (
    FunctionDefinition,
    Undefinition,
)


@dataclass(frozen=True)
class DefineFuncCommand:
    """Input for ``define_func`` — the selector for the function's entry point."""

    address: str


@dataclass(frozen=True)
class DefineFuncResult:
    """Output for ``define_func`` — the completed function creation."""

    definition: FunctionDefinition


@dataclass(frozen=True)
class UndefineCommand:
    """Input for ``undefine`` — the selector for the item to revert to raw bytes."""

    address: str


@dataclass(frozen=True)
class UndefineResult:
    """Output for ``undefine`` — the completed undefine."""

    undefinition: Undefinition
