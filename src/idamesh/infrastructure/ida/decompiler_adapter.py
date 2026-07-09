"""IDA adapter implementing :class:`DecompilerGateway`.

Thin wrapper over ``ida_hexrays``. Lazy ``ida_*`` imports so the module loads
without IDA present. The Hex-Rays plugin is initialized on demand; an absent or
unlicensed decompiler, or a function that cannot be decompiled, is reported by
raising :class:`DecompilationError`, which the interface layer renders as an
``isError`` tool result rather than a protocol fault.
"""

from __future__ import annotations

from idamesh.domain.entities.decompilation import Pseudocode
from idamesh.domain.values.address import Address


class DecompilationError(RuntimeError):
    """Raised when the decompiler is unavailable or a function fails to decompile."""


class IdaDecompilerGateway:
    """:class:`~idamesh.domain.ports.decompiler.DecompilerGateway` over Hex-Rays."""

    def is_available(self) -> bool:
        try:
            import ida_hexrays
        except Exception:
            return False
        try:
            return bool(ida_hexrays.init_hexrays_plugin())
        except Exception:
            return False

    def decompile(self, ea: Address) -> Pseudocode:
        import ida_hexrays
        import ida_lines

        if not self.is_available():
            raise DecompilationError("the Hex-Rays decompiler is not available")

        target = int(ea)
        hf = ida_hexrays.hexrays_failure_t()
        # DECOMP_NO_CACHE builds a private microcode/cfunc for this call instead of
        # sharing IDA's single global decompiler cache. In the resident GUI plugin
        # that isolation is essential: decompiling a function the user has open in a
        # pseudocode view must not evict that view's live cached microcode — doing so
        # is the INTERR 52813 "deleted stale microcode from idb" trigger. DECOMP_NO_WAIT
        # keeps the marshalled call from ever raising a wait-box. Passing an explicit
        # hexrays_failure_t surfaces the failure reason when the result is None.
        flags = ida_hexrays.DECOMP_NO_WAIT | ida_hexrays.DECOMP_NO_CACHE
        try:
            cfunc = ida_hexrays.decompile(target, hf, flags)
        except ida_hexrays.DecompilationFailure as exc:
            raise DecompilationError(f"decompilation failed at {ea.hex()}: {exc}") from exc

        if cfunc is None:
            code = getattr(hf, "code", None)
            raise DecompilationError(
                f"no pseudocode available at {ea.hex()} "
                f"(hexrays failure code={code}; not within a function?)"
            )

        lines = self._pseudocode_lines(cfunc, ida_lines)
        text = "\n".join(lines)
        name = self._entry_name(cfunc, target)
        return Pseudocode(ea=Address(target), text=text, lines=lines, name=name)

    # -- internals ---------------------------------------------------------

    @staticmethod
    def _pseudocode_lines(cfunc, ida_lines) -> tuple[str, ...]:
        """Extract the pseudocode as plain (tag-stripped) text lines.

        The natural path — iterating ``cfunc.get_pseudocode()`` and reading each
        ``simpleline_t.line`` — holds under the full IDA Python bindings (the GUI
        plugin) but *not* under ``idalib`` (the headless worker), where the
        ``strvec_t`` elements come back as untyped ``SwigPyObject`` with no
        ``.line`` attribute. When that typed access is unavailable, fall back to
        ``str(cfunc)`` — ``cfunc_t.__str__`` yields the same pseudocode text in
        every binding — so decompilation works identically headless and in the GUI.
        """
        try:
            sv = cfunc.get_pseudocode()
            lines = [ida_lines.tag_remove(sv[i].line) for i in range(sv.size())]
            if lines:
                return tuple(lines)
        except AttributeError:
            pass
        text = ida_lines.tag_remove(str(cfunc))
        return tuple(text.splitlines())

    @staticmethod
    def _entry_name(cfunc, ea: int) -> str | None:
        try:
            import ida_funcs

            entry = getattr(cfunc, "entry_ea", ea)
            name = ida_funcs.get_func_name(entry)
            return name or None
        except Exception:
            return None
