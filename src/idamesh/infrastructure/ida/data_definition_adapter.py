"""IDA adapter implementing :class:`~idamesh.domain.ports.data_definition.DataDefinitionGateway`.

Backs the ``make_data`` tool. Two paths share one method:

* **Typed** — when a C declaration is supplied it is parsed into a ``tinfo_t``
  (``ida_typeinf.parse_decl``, mirroring the ``set_type`` adapter's ergonomics),
  any prior items across the type's byte span are cleared
  (``ida_bytes.del_items``), and the type is installed at the address
  (``ida_typeinf.apply_tinfo`` under the "definite" flag), which defines the data
  item and sizes it to the type.
* **Sized** — when only a byte width is supplied a primitive item of that width is
  created with the matching ``ida_bytes.create_byte``/``create_word``/
  ``create_dword``/``create_qword`` after clearing the span; only the SDK's native
  widths (1/2/4/8) are supported and any other width is refused.

Both paths report the type in force and the item's byte span afterward (read back
with ``ida_bytes.get_item_size``) so the caller can echo both. A declaration that
will not parse, an unsupported size, or a definition the database refuses raises —
surfaced by the application as an ``isError`` result. All ``ida_*`` imports are
performed lazily inside the method so this module loads without IDA present.
"""

from __future__ import annotations

from typing import Dict, Tuple

from idamesh.domain.values.address import Address

#: Native primitive widths mapped to the ``ida_bytes`` creator name and the label
#: reported as the type in force when no declaration was supplied. Reproduced as
#: interoperability facts; a width outside this set has no primitive and is refused.
_PRIMITIVES: Dict[int, Tuple[str, str]] = {
    1: ("create_byte", "byte"),
    2: ("create_word", "word"),
    4: ("create_dword", "dword"),
    8: ("create_qword", "qword"),
}


class IdaDataDefinitionGateway:
    """:class:`~idamesh.domain.ports.data_definition.DataDefinitionGateway` over the SDK."""

    def make_data(self, ea: Address, type: str, size: int) -> Tuple[str, int]:
        """Define a data item at ``ea``; return ``(applied_type, item_size)``.

        A non-empty ``type`` takes the typed path (parse + apply); otherwise the
        ``size`` byte-width takes the primitive path. The application layer has
        already guaranteed exactly one of the two is usable, but each path guards
        its own precondition so a direct call is still safe.
        """
        if type:
            return self._define_typed(ea, type)
        return self._define_sized(ea, size)

    def _define_typed(self, ea: Address, decl: str) -> Tuple[str, int]:
        """Parse ``decl`` and apply it at ``ea``, defining a typed data item."""
        # Lazy SDK imports keep this module importable without IDA present.
        import ida_bytes
        import ida_typeinf

        address = int(ea)
        til = ida_typeinf.get_idati()
        if til is None:
            raise ValueError("the local type library is unavailable")

        tif = ida_typeinf.tinfo_t()
        # ``PT_SIL`` parses silently (no error dialog on the GUI backend); a parse
        # failure returns ``None`` rather than raising, so it is checked explicitly.
        pt_flags = getattr(ida_typeinf, "PT_SIL", 0)
        # ``parse_decl`` treats the text as a full C declaration and needs the
        # terminating semicolon; a bare form such as ``char[16]`` parses to
        # ``None`` without it, so one is supplied when the caller omitted it.
        text = decl if decl.rstrip().endswith(";") else decl + ";"
        if ida_typeinf.parse_decl(tif, til, text, pt_flags) is None:
            raise ValueError(f"cannot parse type declaration: {decl!r}")

        # Clear any prior items across the type's span so the definition lands on
        # raw bytes; a sizeless type (e.g. incomplete) clears only the head item.
        span = tif.get_size()
        if span is None or span == ida_typeinf.BADSIZE or span <= 0:
            ida_bytes.del_items(address, ida_bytes.DELIT_SIMPLE)
        else:
            ida_bytes.del_items(address, ida_bytes.DELIT_SIMPLE, span)

        if not ida_typeinf.apply_tinfo(
            address, tif, ida_typeinf.TINFO_DEFINITE
        ):
            raise ValueError(f"cannot define data of type {decl!r} at {ea.hex()}")

        applied_type = _type_label(tif) or decl.strip()
        return applied_type, _item_size(ida_bytes, address, span)

    def _define_sized(self, ea: Address, size: int) -> Tuple[str, int]:
        """Create a primitive item of ``size`` bytes at ``ea``."""
        # Lazy SDK import keeps this module importable without IDA present.
        import ida_bytes

        primitive = _PRIMITIVES.get(size)
        if primitive is None:
            supported = "/".join(str(width) for width in sorted(_PRIMITIVES))
            raise ValueError(
                f"unsupported data size {size!r}; expected one of {supported} bytes"
            )
        creator_name, label = primitive

        address = int(ea)
        # Clear the span first so the primitive lands on raw bytes rather than
        # failing against an overlapping definition.
        ida_bytes.del_items(address, ida_bytes.DELIT_SIMPLE, size)

        creator = getattr(ida_bytes, creator_name)
        # The creators take a byte count for the item to define (a single element
        # at these widths); a false return means the item could not be created.
        if not creator(address, size):
            raise ValueError(
                f"cannot create {label} ({size} bytes) at {ea.hex()}"
            )

        return label, _item_size(ida_bytes, address, size)


def _type_label(tif) -> str:
    """Render a parsed ``tinfo_t`` as a declaration string, or ``""`` if it cannot."""
    try:
        label = tif.dstr()
    except Exception:  # pragma: no cover - defensive; dstr is total in practice
        label = ""
    return label or ""


def _item_size(ida_bytes, address: int, fallback: int) -> int:
    """Read the defined item's byte span, falling back to the intended width.

    ``get_item_size`` reports at least one byte for a defined item, so it is the
    authoritative span afterward; a defensive ``fallback`` (the type/primitive
    width) covers the degenerate case where nothing readable was defined.
    """
    span = ida_bytes.get_item_size(address)
    if not span or span <= 0:
        return int(fallback) if fallback and fallback > 0 else 0
    return int(span)
