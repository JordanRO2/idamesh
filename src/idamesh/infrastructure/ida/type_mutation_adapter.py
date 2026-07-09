"""IDA adapter implementing :class:`~idamesh.domain.ports.type_mutation.TypeMutationGateway`.

Parses a C declaration/prototype and applies the resulting type at an address.
The text is parsed into a ``tinfo_t`` with ``ida_typeinf.parse_decl`` against the
database's local type library, then installed on the item with
``ida_typeinf.apply_tinfo`` under the "definite" flag. The item's name afterward
(``ida_name.get_name``) is returned so the caller can report which symbol was
retyped. A declaration that fails to parse, or a type the database refuses to
apply, raises — surfaced by the application as an ``isError`` result. All
``ida_*`` imports are performed lazily inside the method so this module loads
without IDA present.
"""

from __future__ import annotations

from idamesh.domain.values.address import Address


class IdaTypeMutationGateway:
    """:class:`~idamesh.domain.ports.type_mutation.TypeMutationGateway` over the SDK."""

    def apply_type(self, ea: Address, decl: str) -> str:
        # Lazy SDK imports keep this module importable without IDA present.
        import ida_name
        import ida_typeinf

        address = int(ea)
        til = ida_typeinf.get_idati()
        if til is None:
            raise ValueError("the local type library is unavailable")

        tif = ida_typeinf.tinfo_t()
        # ``PT_SIL`` parses silently (no error dialog on the GUI backend); a parse
        # failure returns ``None`` rather than raising, so it is checked explicitly.
        pt_flags = getattr(ida_typeinf, "PT_SIL", 0)
        # ``parse_decl`` treats the text as a full C declaration and requires the
        # terminating semicolon; a bare prototype such as ``int f(int a, int b)``
        # parses to ``None`` without it. Supply one when the caller omitted it so
        # the ergonomic (unterminated) form the contract documents still applies.
        text = decl if decl.rstrip().endswith(";") else decl + ";"
        parsed = ida_typeinf.parse_decl(tif, til, text, pt_flags)
        if parsed is None:
            raise ValueError(f"cannot parse type declaration: {decl!r}")

        if not ida_typeinf.apply_tinfo(
            address, tif, ida_typeinf.TINFO_DEFINITE
        ):
            raise ValueError(f"cannot apply type {decl!r} at {ea.hex()}")

        return ida_name.get_name(address) or ""
