"""The ``declare_type`` use-case: install C type(s) into the local library.

Validates that a non-empty C source was supplied, then hands the bulk parse to the
:class:`~idamesh.domain.ports.type_declaration.TypeDeclarationGateway`, which
returns the names of the types added. No address is involved. The empty-input guard
and the result assembly are the application's; parsing and installation are the
gateway's SDK-level job.
"""

from __future__ import annotations

from idamesh.application.dto.declare_type import (
    DeclareTypeCommand,
    DeclareTypeResult,
)
from idamesh.domain.entities.type_declaration import TypeDeclaration
from idamesh.domain.ports.type_declaration import TypeDeclarationGateway


def _require_declaration(declaration: str) -> str:
    """Return ``declaration`` if it is a non-empty, non-blank string, else raise."""
    if not isinstance(declaration, str):
        raise ValueError(
            f"declaration must be a string, got {type(declaration).__name__}"
        )
    stripped = declaration.strip()
    if not stripped:
        raise ValueError("declaration must not be empty")
    return stripped


class DeclareTypeUseCase:
    """Parse C source and install the resulting types into the local library."""

    def __init__(self, types: TypeDeclarationGateway) -> None:
        self._types = types

    def execute(self, command: DeclareTypeCommand) -> DeclareTypeResult:
        """Install ``command.declaration`` into the local type library.

        The source is checked non-empty, then the type-declaration gateway parses
        it and installs each type, reporting the names added. The completed
        installation is wrapped as a
        :class:`~idamesh.domain.entities.type_declaration.TypeDeclaration`. Source
        that fails to parse surfaces as an error the interface layer renders as an
        ``isError`` result.
        """
        declaration = _require_declaration(command.declaration)
        names = self._types.declare_types(declaration)
        return DeclareTypeResult(declaration=TypeDeclaration(names=tuple(names)))
