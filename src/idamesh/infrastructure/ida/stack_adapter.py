"""IDA adapter implementing :class:`~idamesh.domain.ports.stack.StackGateway`.

Backs the ``declare_stack`` and ``delete_stack`` tools. On IDA ≥ 8.4 a function's
frame is a ``tinfo_t`` UDT: :meth:`declare` parses the member's C type and adds it
to the frame at the requested offset via ``ida_frame`` / ``ida_typeinf``, while
:meth:`delete` removes the named frame member. A function that cannot be found, a
type that will not parse, or a member the frame refuses raises — surfaced by the
application as an ``isError`` result. All ``ida_*`` imports are performed lazily
inside the methods so this module loads without IDA present.
"""

from __future__ import annotations

from idamesh.domain.values.address import Address


class IdaStackGateway:
    """:class:`~idamesh.domain.ports.stack.StackGateway` over the IDA SDK."""

    def declare(self, func: Address, name: str, type: str, offset: int) -> None:
        """Define frame variable ``name`` of C type ``type`` at ``offset``.

        The owning function is located with ``ida_funcs.get_func``; the member type
        is parsed against the local til and placed on the frame at the signed
        ``offset`` (negative for locals, positive for arguments) with
        ``ida_frame.define_stkvar``. A falsey return means the variable could not be
        placed and raises.
        """
        # Lazy SDK imports keep this module importable without IDA present.
        import ida_frame
        import ida_funcs
        import ida_typeinf

        function = ida_funcs.get_func(int(func))
        if function is None:
            raise ValueError(f"no function at {func.hex()}")

        til = ida_typeinf.get_idati()
        tif = ida_typeinf.tinfo_t()
        text = type if type.rstrip().endswith(";") else type + ";"
        pt_flags = getattr(ida_typeinf, "PT_SIL", 0)
        if ida_typeinf.parse_decl(tif, til, text, pt_flags) is None:
            raise ValueError(f"cannot parse stack variable type: {type!r}")

        if not ida_frame.define_stkvar(function, name, offset, tif):
            raise ValueError(
                f"cannot define stack variable {name!r} at offset {offset} of "
                f"the function at {func.hex()}"
            )

    def delete(self, func: Address, name: str) -> None:
        """Remove frame variable ``name`` from the function at ``func``.

        The owning function is located, its frame walked for the named member, and
        the member deleted with ``ida_frame.delete_frame_members`` over the member's
        byte span. A member the frame does not carry, or a failed delete, raises.
        """
        # Lazy SDK imports keep this module importable without IDA present.
        import ida_frame
        import ida_funcs
        import ida_typeinf

        function = ida_funcs.get_func(int(func))
        if function is None:
            raise ValueError(f"no function at {func.hex()}")

        # ``get_func_frame`` fills an out ``tinfo_t`` and returns whether the
        # function carries a frame; the frame itself is the UDT we then walk.
        frame = ida_typeinf.tinfo_t()
        if not ida_frame.get_func_frame(frame, function):
            raise ValueError(f"the function at {func.hex()} has no frame")

        member = _find_member(frame, name)
        if member is None:
            raise ValueError(
                f"the function at {func.hex()} has no stack variable {name!r}"
            )
        start, end = member
        if not ida_frame.delete_frame_members(function, start, end):
            raise ValueError(
                f"cannot delete stack variable {name!r} of the function at "
                f"{func.hex()}"
            )


def _find_member(frame, name: str):
    """Return the ``(start_offset, end_offset)`` of frame member ``name``, or None."""
    udt = _udt_data(frame)
    if udt is None:
        return None
    for member in udt:
        if member.name == name:
            start = member.offset // 8
            end = start + member.size // 8
            return start, end
    return None


def _udt_data(frame):
    """Read a frame ``tinfo_t``'s member list, or ``None`` when unavailable."""
    import ida_typeinf

    data = ida_typeinf.udt_type_data_t()
    if not frame.get_udt_details(data):
        return None
    return data
