"""IDA adapter implementing :class:`XrefRepository`.

Backs both ``xrefs_to`` and ``callees``: :meth:`refs_to` iterates the SDK's
inbound cross-reference walk and attributes each source to its owning function;
:meth:`callees` walks the owning function's instructions and collects the unique
call targets. All ``ida_*`` imports are performed lazily inside the methods so
this module loads without IDA present.

Reference classification uses two independent facts the SDK exposes on each
edge: a code/data flag, and a numeric type whose meaning (call/jump for code,
read/write/offset for data) is the SDK's own taxonomy. We mask the type to its
base value before comparing, since the walk may OR in user/tail flags.
"""

from __future__ import annotations

from typing import List, Optional, Set, Tuple

from idamesh.domain.entities.xref import Xref, XrefKind, XrefType
from idamesh.domain.values.address import Address

#: Fallback for the SDK's base-type mask when the constant is not exported.
_TYPE_MASK: int = 0x1F


class XrefError(RuntimeError):
    """Raised when a callee query anchors on an address inside no function.

    The interface layer turns this into an ``isError`` tool result rather than a
    protocol fault, mirroring how the decompiler adapter reports a missing
    function.
    """


class IdaXrefRepository:
    """:class:`~idamesh.domain.ports.xrefs.XrefRepository` over the IDA SDK."""

    def refs_to(self, ea: Address) -> List[Xref]:
        import ida_xref
        import idautils

        target = int(ea)
        mask = getattr(ida_xref, "XREF_MASK", _TYPE_MASK)
        out: List[Xref] = []
        for ref in idautils.XrefsTo(target, 0):
            try:
                source = Address(int(ref.frm))
                to = Address(int(ref.to))
            except ValueError:
                # Skip an edge whose endpoint is the invalid sentinel.
                continue
            kind, ref_type = _classify(bool(ref.iscode), int(ref.type) & mask, ida_xref)
            out.append(
                Xref(
                    source=source,
                    target=to,
                    kind=kind,
                    ref_type=ref_type,
                    source_func=_func_name_at(int(ref.frm)),
                )
            )
        return out

    def callees(self, ea: Address) -> List[Xref]:
        import ida_funcs
        import ida_xref
        import idautils

        anchor = int(ea)
        func = ida_funcs.get_func(anchor)
        if func is None:
            raise XrefError(
                f"no function contains {ea.hex()}; callees needs an address "
                "inside a function"
            )

        mask = getattr(ida_xref, "XREF_MASK", _TYPE_MASK)
        call_types: Tuple[int, ...] = (ida_xref.fl_CF, ida_xref.fl_CN)
        seen: Set[int] = set()
        out: List[Xref] = []
        for head in idautils.Heads(func.start_ea, func.end_ea):
            for ref in idautils.XrefsFrom(head, 0):
                if not ref.iscode:
                    continue
                if (int(ref.type) & mask) not in call_types:
                    continue
                target = int(ref.to)
                if target in seen:
                    # Collapse repeated calls to the same target across the body.
                    continue
                seen.add(target)
                try:
                    source = Address(int(ref.frm))
                    dst = Address(target)
                except ValueError:
                    continue
                out.append(
                    Xref(
                        source=source,
                        target=dst,
                        kind=XrefKind.CODE,
                        ref_type=XrefType.CALL,
                        target_name=_name_at(target),
                    )
                )
        return out


def _classify(iscode: bool, xref_type: int, ida_xref) -> Tuple[XrefKind, XrefType]:
    """Map an SDK edge's code flag and base type onto the domain axes."""
    if iscode:
        if xref_type in (ida_xref.fl_CF, ida_xref.fl_CN):
            return XrefKind.CODE, XrefType.CALL
        if xref_type in (ida_xref.fl_JF, ida_xref.fl_JN):
            return XrefKind.CODE, XrefType.JUMP
        return XrefKind.CODE, XrefType.ORDINARY
    if xref_type == ida_xref.dr_W:
        return XrefKind.DATA, XrefType.WRITE
    if xref_type == ida_xref.dr_R:
        return XrefKind.DATA, XrefType.READ
    if xref_type == ida_xref.dr_O:
        return XrefKind.DATA, XrefType.OFFSET
    return XrefKind.DATA, XrefType.ORDINARY


def _func_name_at(ea: int) -> Optional[str]:
    """Name of the function containing ``ea``, or ``None`` when outside one."""
    try:
        import ida_funcs

        func = ida_funcs.get_func(ea)
        if func is None:
            return None
        name = ida_funcs.get_func_name(func.start_ea)
        return name or None
    except Exception:
        return None


def _name_at(ea: int) -> Optional[str]:
    """Best-available name at ``ea`` — a function name first, else any label."""
    try:
        import ida_funcs

        name = ida_funcs.get_func_name(ea)
        if name:
            return name
    except Exception:
        pass
    try:
        import idc

        label = idc.get_name(ea)
        return label or None
    except Exception:
        return None
