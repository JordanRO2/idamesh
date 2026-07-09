"""Catalog registration and wire-shape projection for ``declare_type`` (mutating).

The ``DeclareTypeView`` ``TypedDict`` gives the schema compiler an object-rooted
``outputSchema``; :func:`declare_type_view` renders the completed installation into
that flat shape (``ok`` always true on success, ``count`` derived from ``names``).
The tool is marked ``@registry.mutating`` so its advertised ``readOnlyHint`` is
``false``. The field names mirror the interoperability contract; the projection is
ours.
"""

from __future__ import annotations

from typing import List, TypedDict

from idamesh.application.contexts.declare_type import DeclareTypeUseCase
from idamesh.application.dto.declare_type import DeclareTypeCommand
from idamesh.domain.entities.type_declaration import TypeDeclaration
from idamesh.domain.ports.execution import MainThreadExecutor
from idamesh.interface.catalog._support import run_mutation
from idamesh.interface.mcp.registry import Registry


class DeclareTypeView(TypedDict):
    """The outcome of one ``declare_type`` call."""

    ok: bool
    count: int
    names: List[str]


def declare_type_view(declaration: TypeDeclaration) -> DeclareTypeView:
    """Project a :class:`TypeDeclaration` into its wire shape."""
    return DeclareTypeView(
        ok=True,
        count=declaration.count,
        names=list(declaration.names),
    )


def register_declare_type(
    registry: Registry,
    *,
    declare_type_use_case: DeclareTypeUseCase,
    executor: MainThreadExecutor,
) -> None:
    """Register ``declare_type`` against the declare-type use-case (mutating)."""

    @registry.tool(name="declare_type")
    @registry.mutating
    def declare_type(declaration: str) -> DeclareTypeView:
        """Install C type declaration(s) into the local type library. The
        ``declaration`` is C source that may contain one or more type declarations
        (``struct``, ``union``, ``enum``, ``typedef``, …), parsed against the local
        type library. The result reports ``ok``, the ``count`` of types added, and
        their ``names``. This modifies the database. Source that fails to parse
        yields an error result rather than failing the protocol request."""
        command = DeclareTypeCommand(declaration=declaration)
        result = run_mutation(
            executor, lambda: declare_type_use_case.execute(command)
        )
        return declare_type_view(result.declaration)
