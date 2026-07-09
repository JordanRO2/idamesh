"""IDA adapter implementing :class:`~idamesh.domain.ports.type_declaration.TypeDeclarationGateway`.

Backs the ``declare_type`` tool. :meth:`declare_types` parses a C source text into
the local type library with ``ida_typeinf.parse_decls`` and reports the names of
the types that landed. A non-zero error count from the parser means the source did
not fully parse and raises — surfaced by the application as an ``isError`` result.
All ``ida_*`` imports are performed lazily inside the method so this module loads
without IDA present.
"""

from __future__ import annotations

from typing import Tuple

from idamesh.domain.values.address import Address  # noqa: F401 — reserved for parity


class IdaTypeDeclarationGateway:
    """:class:`~idamesh.domain.ports.type_declaration.TypeDeclarationGateway` over the SDK."""

    def declare_types(self, declaration: str) -> Tuple[str, ...]:
        """Parse ``declaration`` into the local til; return the type names added.

        ``ida_typeinf.parse_decls`` installs each parsed declaration into the local
        type library and returns the number of parse errors; a non-zero count
        raises. The names added are recovered by diffing the local type ordinals
        around the parse so the caller can report them.
        """
        # Lazy SDK import keeps this module importable without IDA present.
        import ida_typeinf

        til = ida_typeinf.get_idati()
        if til is None:
            raise ValueError("the local type library is unavailable")

        before = _ordinal_names(ida_typeinf, til)
        flags = getattr(ida_typeinf, "HTI_DCL", 0)
        errors = ida_typeinf.parse_decls(til, declaration, None, flags)
        if errors:
            raise ValueError(
                f"cannot parse type declaration ({errors} error(s)): "
                f"{declaration!r}"
            )
        after = _ordinal_names(ida_typeinf, til)
        added = tuple(name for name in after if name not in before)
        return added


def _ordinal_names(ida_typeinf, til) -> Tuple[str, ...]:
    """Snapshot the names of every numbered type in ``til``."""
    count = ida_typeinf.get_ordinal_count(til)
    names = []
    for ordinal in range(1, count + 1):
        name = ida_typeinf.get_numbered_type_name(til, ordinal)
        if name:
            names.append(name)
    return tuple(names)
