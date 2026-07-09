"""Command/Result DTOs for the ``declare_type`` tool.

``DeclareTypeCommand`` carries the C source ``declaration`` to install;
``DeclareTypeResult`` wraps the resulting
:class:`~idamesh.domain.entities.type_declaration.TypeDeclaration`. No address is
involved — the use-case validates the source is non-empty and routes it through
the type-declaration gateway.
"""

from __future__ import annotations

from dataclasses import dataclass

from idamesh.domain.entities.type_declaration import TypeDeclaration


@dataclass(frozen=True)
class DeclareTypeCommand:
    """Input for ``declare_type`` — C source with one or more declarations."""

    declaration: str


@dataclass(frozen=True)
class DeclareTypeResult:
    """Output for ``declare_type`` — the completed type installation."""

    declaration: TypeDeclaration
