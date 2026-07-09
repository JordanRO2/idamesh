"""IDA adapter implementing :class:`~idamesh.domain.ports.comments.CommentGateway`.

Writes a comment into one of two slots at an address. An item comment maps to
``ida_bytes.set_cmt(ea, text, repeatable)``; a function comment first locates the
owning function via ``ida_funcs.get_func`` and writes through
``ida_funcs.set_func_cmt(func, text, repeatable)``. A function comment requested at
an address in no function, or a write the database refuses, raises — surfaced by
the application as an ``isError`` result. All ``ida_*`` imports are performed
lazily inside the method so this module loads without IDA present.
"""

from __future__ import annotations

from idamesh.domain.values.address import Address


class IdaCommentGateway:
    """:class:`~idamesh.domain.ports.comments.CommentGateway` over the IDA SDK."""

    def set_comment(
        self,
        ea: Address,
        comment: str,
        *,
        repeatable: bool,
        function: bool,
    ) -> None:
        # Lazy SDK imports keep this module importable without IDA present.
        address = int(ea)

        if function:
            import ida_funcs

            func = ida_funcs.get_func(address)
            if func is None:
                raise ValueError(
                    f"no function contains {ea.hex()}: cannot set a function comment"
                )
            if not ida_funcs.set_func_cmt(func, comment, repeatable):
                raise ValueError(f"failed to set function comment at {ea.hex()}")
            return

        import ida_bytes

        if not ida_bytes.set_cmt(address, comment, repeatable):
            raise ValueError(f"failed to set comment at {ea.hex()}")
