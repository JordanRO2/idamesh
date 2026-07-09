"""IDA adapter implementing :class:`~idamesh.domain.ports.recompile.RecompileGateway`.

Backs the ``force_recompile`` tool. :meth:`recompile` locates the function covering
the address and drops its cached Hex-Rays decompilation with
``ida_hexrays.mark_cfunc_dirty`` so the next ``decompile`` regenerates fresh
pseudocode. An address in no function, or an unavailable decompiler, raises —
surfaced by the application as an ``isError`` result. All ``ida_*`` imports are
performed lazily inside the method so this module loads without IDA present.
"""

from __future__ import annotations

from idamesh.domain.values.address import Address


class IdaRecompileGateway:
    """:class:`~idamesh.domain.ports.recompile.RecompileGateway` over the IDA SDK."""

    def recompile(self, ea: Address) -> None:
        """Invalidate the cached decompilation of the function covering ``ea``.

        The enclosing function is located with ``ida_funcs.get_func``; its cached
        ``cfunc`` is marked dirty with ``ida_hexrays.mark_cfunc_dirty`` (a no-op
        when nothing is cached, which still satisfies the invalidation contract).
        An address in no function, or a decompiler that will not initialize, raises.
        """
        # Lazy SDK imports keep this module importable without IDA present.
        import ida_funcs
        import ida_hexrays

        if not ida_hexrays.init_hexrays_plugin():
            raise ValueError("the decompiler is unavailable")

        function = ida_funcs.get_func(int(ea))
        if function is None:
            raise ValueError(f"{ea.hex()} is not inside a function")

        ida_hexrays.mark_cfunc_dirty(function.start_ea)
