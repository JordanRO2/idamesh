"""IDA adapter implementing :class:`~idamesh.domain.ports.script.ScriptRunner`.

Backs the ``exec_python`` tool. The script executes in a namespace pre-populated
with the common IDAPython modules (``idaapi`` / ``idc`` / ``idautils`` and the
``ida_*`` family); whatever it ``print``s is captured, and a ``result`` name it
binds is repr'd back to the caller. The whole run happens on the database-owning
thread (the application marshals it through ``run_mutation``), so a script may
both read and mutate the database. A script that raises is re-raised with its
captured output and formatted traceback so the interface renders an ``isError``
result carrying the failure. All ``ida_*`` imports are lazy so this module loads
without IDA present.
"""

from __future__ import annotations

import builtins
import contextlib
import io
import traceback

from idamesh.domain.ports.script import ScriptOutcome

#: ``ida_*`` submodules injected into the script namespace by name, so a script
#: can reach them without an explicit ``import``. An absent module is skipped.
_IDA_MODULES = (
    "ida_funcs", "ida_bytes", "ida_name", "ida_kernwin", "ida_ua", "ida_typeinf",
    "ida_frame", "ida_segment", "ida_xref", "ida_nalt", "ida_hexrays", "ida_gdl",
    "ida_idaapi", "ida_ida", "ida_search", "ida_entry", "ida_struct",
)


class IdaScriptGateway:
    """:class:`~idamesh.domain.ports.script.ScriptRunner` over the IDA SDK."""

    def run(self, code: str) -> ScriptOutcome:
        """Execute ``code`` with IDAPython in scope; capture stdout + ``result``.

        The namespace exposes ``idaapi``, ``idc``, ``idautils`` and the ``ida_*``
        modules a script commonly needs, plus the full builtins. Standard output is
        redirected into a buffer for the duration of the run. On success the buffer
        and the ``repr`` of any ``result`` binding are returned; on failure the
        captured output and the formatted traceback are raised as a ``RuntimeError``
        so the caller sees exactly where the script broke.
        """
        # Lazy SDK imports keep this module importable without IDA present.
        import idaapi
        import idautils
        import idc

        namespace: dict = {
            "__name__": "__idamesh_exec__",
            "__builtins__": builtins,
            "idaapi": idaapi,
            "idc": idc,
            "idautils": idautils,
        }
        for mod in _IDA_MODULES:
            try:
                namespace[mod] = __import__(mod)
            except Exception:  # noqa: BLE001 — an absent module is simply not injected
                pass

        buffer = io.StringIO()
        try:
            with contextlib.redirect_stdout(buffer):
                exec(compile(code, "<exec_python>", "exec"), namespace)
        except Exception:  # noqa: BLE001 — surfaced to the client as isError
            out = buffer.getvalue()
            raise RuntimeError((out + "\n" if out else "") + traceback.format_exc()) from None

        result = namespace.get("result")
        return ScriptOutcome(
            stdout=buffer.getvalue(),
            result="" if result is None else repr(result),
        )
