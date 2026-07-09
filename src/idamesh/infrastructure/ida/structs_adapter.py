"""IDA adapter implementing :class:`~idamesh.domain.ports.structs.StructGateway`.

Enumerates the database's aggregate (struct/union) types through IDA's type API
(``ida_typeinf``): the numbered-type ordinals of the default type library are
walked (``get_ordinal_count`` / ``tinfo_t.get_numbered_type``), each resolved to a
``tinfo_t`` and kept when it is a UDT; :meth:`list_structs` summarizes each as a
:class:`~idamesh.domain.entities.struct_summary.StructSummary` and :meth:`layout`
resolves one named aggregate (``tinfo_t.get_named_type``) and expands its members
(``get_udt_details`` → ``udt_type_data_t`` / ``udm_t``) into a
:class:`~idamesh.domain.entities.struct_layout.StructLayout`. Member offsets and
sizes are reported by the SDK in bits and converted to bytes here. All ``ida_*``
imports are performed lazily inside the methods so this module loads without IDA
present; a binary may declare few or no user structs, so an empty result is valid
rather than an error.
"""

from __future__ import annotations

from typing import List, Optional

from idamesh.domain.entities.struct_layout import StructField, StructLayout
from idamesh.domain.entities.struct_summary import StructSummary

#: Bits per byte, for converting the SDK's bit-granular member geometry.
_BITS_PER_BYTE = 8


class IdaStructGateway:
    """:class:`~idamesh.domain.ports.structs.StructGateway` over the IDA SDK."""

    def list_structs(self, query: str, limit: int) -> List[StructSummary]:
        # Lazy SDK import keeps this module importable without IDA present.
        import ida_typeinf

        out: List[StructSummary] = []
        if limit <= 0:
            return out

        needle = query.casefold()
        til = ida_typeinf.get_idati()
        if til is None:
            # No default type library (e.g. before analysis): no structs to list.
            return out
        count = ida_typeinf.get_ordinal_count(til)
        for ordinal in range(1, count + 1):
            tif = ida_typeinf.tinfo_t()
            if not tif.get_numbered_type(til, ordinal):
                continue
            if not tif.is_udt():
                # Only aggregate (struct/union) types are in scope; skip
                # typedefs, enums, pointers, and other numbered entries.
                continue
            name = tif.get_type_name()
            if not name:
                continue
            if needle not in name.casefold():
                continue
            out.append(
                StructSummary(
                    name=name,
                    size=_byte_size(tif.get_size()),
                    member_count=_member_count(tif),
                )
            )
            if len(out) >= limit:
                # The caller bounds the reply; stop once the cap is reached.
                break
        return out

    def layout(self, name: str) -> Optional[StructLayout]:
        # Lazy SDK import keeps this module importable without IDA present.
        import ida_typeinf

        til = ida_typeinf.get_idati()
        if til is None:
            # No default type library: the name cannot bind to anything.
            return None
        tif = ida_typeinf.tinfo_t()
        if not tif.get_named_type(til, name):
            # No type binds this name.
            return None
        if not tif.is_udt():
            # The name resolves, but not to an aggregate we can lay out.
            return None

        details = ida_typeinf.udt_type_data_t()
        fields: List[StructField] = []
        if tif.get_udt_details(details):
            for udm in details:
                member = udm.type
                fields.append(
                    StructField(
                        name=udm.name or "",
                        type_name=member.dstr() or "",
                        offset=int(udm.offset) // _BITS_PER_BYTE,
                        size=_member_byte_size(member, udm.size),
                    )
                )

        return StructLayout(
            name=tif.get_type_name() or name,
            size=_byte_size(tif.get_size()),
            fields=tuple(fields),
        )


def _byte_size(size: int) -> int:
    """Normalize a ``tinfo_t.get_size`` result to a non-negative byte count.

    The SDK reports ``BADSIZE`` for a type whose width it cannot determine; that
    sentinel (and any negative) collapses to ``0`` so the reported size is always a
    plain, safe-to-serialize byte count.
    """
    value = int(size)
    if value < 0 or value == _BAD_SIZE:
        return 0
    return value


def _member_byte_size(member_type: object, size_bits: int) -> int:
    """Byte width of a UDT member.

    Prefers the member type's own byte size (which counts a bitfield's storage
    unit and an array's or nested aggregate's full footprint); falls back to the
    SDK's bit-granular member size divided down when the type width is
    indeterminate.
    """
    declared = int(member_type.get_size())  # type: ignore[attr-defined]
    if 0 < declared != _BAD_SIZE:
        return declared
    bits = int(size_bits)
    return bits // _BITS_PER_BYTE if bits > 0 else 0


def _member_count(tif: object) -> int:
    """Number of members in an aggregate, floored at ``0``.

    ``tinfo_t.get_udt_nmembers`` returns ``-1`` for a non-UDT; callers only reach
    here for aggregates, but the floor keeps a malformed reply from leaking a
    negative count into the summary.
    """
    count = int(tif.get_udt_nmembers())  # type: ignore[attr-defined]
    return count if count > 0 else 0


#: ``ida_typeinf.BADSIZE`` — the SDK's "unknown width" sentinel (``2**64 - 1``).
#: Duplicated as a module constant so the pure helpers above need no SDK import.
_BAD_SIZE = 0xFFFFFFFFFFFFFFFF
