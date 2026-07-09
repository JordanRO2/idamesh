"""Templated code resources keyed by address.

Three URI templates surface the address-keyed code reads as browsable MCP
resources: ``ida://function/{address}`` (Hex-Rays pseudocode via
:class:`DecompileUseCase`), ``ida://disasm/{address}`` (bounded linear
disassembly via :class:`DisasmUseCase`), and ``ida://xrefs/{address}`` (inbound
cross-references via :class:`XrefsToUseCase`). Each is a second projection of an
existing read — no new domain code — and reuses the tool catalog's wire view
verbatim (:func:`decompile_view`, :func:`disasm_view`, :func:`xrefs_to_view`).

Each ``{address}`` token captures exactly one path segment and arrives as a
string — a hex literal (``0x…``), a decimal literal, or a symbol name — which is
handed straight to the command; the use-case resolves it. Every handler marshals
its use-case onto the kernel thread through :func:`run_use_case`, so a bad target
(an unresolvable address, an address outside any function, an unavailable
decompiler) is raised as a :class:`ToolError` and the engine renders it as a
``resources/read`` resource-not-found error, never a tool ``isError`` envelope.
"""

from __future__ import annotations

from idamesh.application.contexts.decompiler import DecompileUseCase
from idamesh.application.contexts.disasm import DisasmUseCase
from idamesh.application.contexts.xrefs import XrefsToUseCase
from idamesh.application.dto.decompiler import DecompileCommand
from idamesh.application.dto.disasm import DisasmCommand
from idamesh.application.dto.xrefs import XrefsToCommand
from idamesh.domain.ports.execution import MainThreadExecutor
from idamesh.interface.catalog.disasm import DisasmView, disasm_view
from idamesh.interface.catalog.resources._support import run_use_case
from idamesh.interface.catalog.views import DecompileView, decompile_view
from idamesh.interface.catalog.xrefs import XrefsToView, xrefs_to_view
from idamesh.interface.mcp.registry import Registry

#: The URI templates of the three address-keyed code resources.
FUNCTION_URI_TEMPLATE = "ida://function/{address}"
DISASM_URI_TEMPLATE = "ida://disasm/{address}"
XREFS_URI_TEMPLATE = "ida://xrefs/{address}"


def register_code_resources(
    registry: Registry,
    *,
    decompile_use_case: DecompileUseCase,
    disasm_use_case: DisasmUseCase,
    xrefs_to_use_case: XrefsToUseCase,
    executor: MainThreadExecutor,
) -> None:
    """Register ``ida://function|disasm|xrefs/{address}`` templates."""

    @registry.resource(FUNCTION_URI_TEMPLATE, name="function")
    def function(address: str) -> DecompileView:
        """Hex-Rays pseudocode for the function at ``address``, offered as a
        browsable resource keyed by address. The ``address`` path segment is a
        hex literal (``0x…``), a decimal literal, or a symbol name; it is
        resolved to a function entry before decompiling. The payload carries the
        function ``name`` and resolved ``address`` (``0x`` hex), the joined
        ``pseudocode`` text, and its individual source ``lines`` — the same
        projection the ``decompile`` tool returns. An address outside any
        function, or an unavailable decompiler, yields a resource-not-found
        error."""
        result = run_use_case(
            executor,
            lambda: decompile_use_case.execute(DecompileCommand(address=address)),
        )
        return decompile_view(result.pseudocode)

    @registry.resource(DISASM_URI_TEMPLATE, name="disasm")
    def disasm(address: str) -> DisasmView:
        """Bounded linear disassembly starting at ``address``, offered as a
        browsable resource keyed by address. The ``address`` path segment is a
        hex literal (``0x…``), a decimal literal, or a symbol name; it is
        resolved to the first instruction listed, and a server default bounds how
        many instructions are rendered. Each row carries its ``addr``, the opcode
        ``bytes`` as a hex string, and the rendered instruction ``text``; the
        payload also reports how many were ``returned`` and a ``truncated`` flag —
        the same projection the ``disasm`` tool returns. An out-of-range or
        unresolvable address yields a resource-not-found error."""
        result = run_use_case(
            executor,
            lambda: disasm_use_case.execute(DisasmCommand(address=address)),
        )
        return disasm_view(result)

    @registry.resource(XREFS_URI_TEMPLATE, name="xrefs")
    def xrefs(address: str) -> XrefsToView:
        """Cross-references that point at ``address``, offered as a browsable
        resource keyed by address. The ``address`` path segment is a hex literal
        (``0x…``), a decimal literal, or a symbol name; it is resolved to a
        concrete ``target`` first. Each edge carries the referring ``from``
        address, the enclosing ``func`` name when the source is inside a function,
        the ``kind`` (``code``/``data``), and the finer ``type``
        (``call``/``jump``/``read``/``write``/…); the payload also reports a
        ``truncated`` flag when a per-call cap elided some edges — the same
        projection the ``xrefs_to`` tool returns. An out-of-range or unresolvable
        address yields a resource-not-found error."""
        result = run_use_case(
            executor,
            lambda: xrefs_to_use_case.execute(XrefsToCommand(address=address)),
        )
        return xrefs_to_view(result)
