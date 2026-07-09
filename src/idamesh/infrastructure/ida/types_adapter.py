"""IDA adapter implementing :class:`~idamesh.domain.ports.types.TypeGateway`.

Walks the database's local type library through IDA's type API
(``ida_typeinf``): the numbered-type ordinals of the default ``til`` are
enumerated (``get_ordinal_count`` / ``get_numbered_type``), each resolved to a
``tinfo_t`` whose kind, byte size, and — for aggregates — UDT member layout
(``get_udt_details``) populate a
:class:`~idamesh.domain.entities.type_info.TypeInfo`. All ``ida_*`` imports are
performed lazily inside the methods so this module loads without IDA present; the
type catalog may be sparse (a small binary can carry few user types), so an empty
result is valid rather than an error.
"""

from __future__ import annotations

from typing import List, Optional

from idamesh.domain.entities.type_info import TypeInfo, TypeMember

#: Number of bits in one byte, used to fold IDA's bit-granular member offsets and
#: sizes back down to the byte quantities the wire shapes report.
_BITS_PER_BYTE: int = 8


class IdaTypeGateway:
    """:class:`~idamesh.domain.ports.types.TypeGateway` over the IDA SDK."""

    def list_types(self, query: str, limit: int) -> List[TypeInfo]:
        # Lazy SDK import keeps this module importable without IDA present.
        import ida_typeinf

        if limit <= 0:
            return []

        til = ida_typeinf.get_idati()
        if til is None:
            return []

        needle = query.casefold()
        out: List[TypeInfo] = []
        count = ida_typeinf.get_ordinal_count(til)
        for ordinal in range(1, count + 1):
            tif = ida_typeinf.tinfo_t()
            if not tif.get_numbered_type(til, ordinal):
                continue
            name = tif.get_type_name() or ""
            if not name:
                # Anonymous numbered types cannot be looked up by name; skip them.
                continue
            if needle and needle not in name.casefold():
                continue
            # ``type_query`` projects only name/kind/size, so member layout is
            # left out of the enumeration to keep it cheap.
            out.append(
                _type_info(tif, name, ida_typeinf, with_members=False)
            )
            if len(out) >= limit:
                break
        return out

    def get_type(self, name: str) -> Optional[TypeInfo]:
        # Lazy SDK import keeps this module importable without IDA present.
        import ida_typeinf

        if not name:
            return None

        til = ida_typeinf.get_idati()
        if til is None:
            return None

        tif = ida_typeinf.tinfo_t()
        if not tif.get_named_type(til, name):
            return None
        resolved = tif.get_type_name() or name
        return _type_info(tif, resolved, ida_typeinf, with_members=True)


def _type_info(tif, name: str, ida_typeinf, *, with_members: bool) -> TypeInfo:
    """Build a :class:`TypeInfo` from a resolved ``tinfo_t``.

    ``with_members`` gates the (comparatively expensive) UDT member walk so the
    enumeration path can skip it; member detail is populated only for aggregate
    kinds regardless.
    """
    return TypeInfo(
        name=name,
        kind=_classify_kind(tif),
        size=_byte_size(tif, ida_typeinf),
        members=_members(tif, ida_typeinf) if with_members else (),
    )


def _classify_kind(tif) -> str:
    """Reduce a ``tinfo_t`` to a coarse kind token.

    Aggregate and named kinds are tested before ``is_typeref`` because a named
    struct/union/enum in the local library also reports as a type reference; the
    concrete kind is the more useful label.
    """
    if tif.is_struct():
        return "struct"
    if tif.is_union():
        return "union"
    if tif.is_enum():
        return "enum"
    if tif.is_func():
        return "function"
    if tif.is_ptr():
        return "pointer"
    if tif.is_array():
        return "array"
    if tif.is_bitfield():
        return "bitfield"
    if tif.is_typeref():
        return "typedef"
    return "scalar"


def _byte_size(tif, ida_typeinf) -> int:
    """Return a type's byte width, mapping IDA's ``BADSIZE`` sentinel to ``0``."""
    size = tif.get_size()
    if size is None or size == ida_typeinf.BADSIZE:
        return 0
    return int(size)


def _members(tif, ida_typeinf) -> tuple:
    """Extract the ordered member layout of an aggregate type.

    Non-aggregates (and aggregates whose detail cannot be read) yield an empty
    tuple. Member offsets and sizes come from the SDK in bits and are folded back
    to bytes; a member's own type size is preferred, falling back to the reported
    bit size when the type is sizeless.
    """
    if not (tif.is_struct() or tif.is_union()):
        return ()

    udt = ida_typeinf.udt_type_data_t()
    if not tif.get_udt_details(udt):
        return ()

    members: List[TypeMember] = []
    for udm in udt:
        member_type = udm.type
        size = member_type.get_size()
        if size is None or size == ida_typeinf.BADSIZE:
            size = udm.size // _BITS_PER_BYTE
        members.append(
            TypeMember(
                name=udm.name or "",
                type_name=_type_label(member_type),
                offset=int(udm.offset // _BITS_PER_BYTE),
                size=int(size),
            )
        )
    return tuple(members)


def _type_label(tif) -> str:
    """Render a member's type as a declaration string."""
    try:
        label = tif.dstr()
    except Exception:  # pragma: no cover - defensive; dstr is total in practice
        label = ""
    return label or str(tif)
