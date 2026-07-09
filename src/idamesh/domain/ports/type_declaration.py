"""The type-declaration gateway port: install C type(s) into the local library.

Backs the ``declare_type`` tool, and is the *bulk parse* counterpart to
:class:`~idamesh.domain.ports.type_mutation.TypeMutationGateway` (which applies a
single type at an address). :meth:`declare_types` parses one C source text — which
may contain several declarations — into the database's local type library and
returns the names of the types added or updated, so the caller can report how many
landed and which. Source that will not parse raises a domain error the caller
surfaces as an ``isError`` result. The SDK-level ``parse_decls`` is the adapter's
job; this port only fixes the contract.
"""

from __future__ import annotations

from typing import Protocol, Tuple


class TypeDeclarationGateway(Protocol):
    """Write-side installation of parsed C types into the local type library."""

    def declare_types(self, declaration: str) -> Tuple[str, ...]:
        """Parse ``declaration`` into the local til; return the type names added.

        ``declaration`` is C source containing one or more type declarations. On
        success each parsed type is installed in the local type library and the
        returned tuple names them in declaration order (empty when the source is
        valid but declares no named type). Raises an error (surfaced by the caller
        as an ``isError`` result) when the source fails to parse.
        """
        ...
