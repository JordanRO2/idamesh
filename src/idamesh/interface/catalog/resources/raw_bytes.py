"""Reference **template** resource: ``ida://bytes/{address}/{size}`` (get_bytes).

This is the canonical pattern the templated-resource builders mirror. A template
resource carries ``{param}`` tokens in its URI; the engine matches the concrete
URI with a per-template regex (each ``{param}`` captures one path segment,
``[^/]+``) and binds every captured value as a **string**. Because the schema
compiler's ``int`` coercer rejects a string, a numeric path param is declared
``str`` on the handler and parsed inside it (here ``size`` via ``int(size, 0)``,
which accepts ``16`` and ``0x10``). A bad target — an unparseable size, an
unresolvable address, or an unreadable region — is raised as a ``ToolError`` and
the engine renders it as a ``resources/read`` resource-not-found error.
"""

from __future__ import annotations

from idamesh.application.contexts.memory import GetBytesUseCase
from idamesh.application.dto.memory import GetBytesCommand
from idamesh.domain.ports.execution import MainThreadExecutor
from idamesh.interface.catalog.get_bytes import GetBytesView, get_bytes_view
from idamesh.interface.catalog.resources._support import run_use_case
from idamesh.interface.mcp.engine import ToolError
from idamesh.interface.mcp.registry import Registry

#: The URI template of the raw-bytes resource (two path params).
BYTES_URI_TEMPLATE = "ida://bytes/{address}/{size}"


def _parse_size(size: str) -> int:
    """Parse the ``{size}`` path segment (decimal or ``0x`` hex); reject the rest."""
    try:
        parsed = int(size, 0)
    except (TypeError, ValueError):
        raise ToolError(f"invalid byte count {size!r}: expected a decimal or 0x literal")
    if parsed <= 0:
        raise ToolError(f"invalid byte count {size!r}: must be positive")
    return parsed


def register_bytes_resource(
    registry: Registry,
    *,
    get_bytes_use_case: GetBytesUseCase,
    executor: MainThreadExecutor,
) -> None:
    """Register ``ida://bytes/{address}/{size}`` against the byte-read use-case."""

    @registry.resource(BYTES_URI_TEMPLATE, name="bytes")
    def read_bytes(address: str, size: str) -> GetBytesView:
        """Read ``size`` raw bytes starting at ``address`` as a browsable
        resource. ``address`` is a URI path segment — a hex literal (``0x…``), a
        decimal literal, or a symbol name — and ``size`` is a decimal or ``0x``
        byte count. The payload echoes the resolved ``address`` (``0x`` hex) and
        ``size`` and returns the ``bytes`` as a lowercase hex string, identical to
        the ``get_bytes`` tool. An unparseable size, an unresolvable address, or
        an unreadable region yields a resource-not-found error."""
        command = GetBytesCommand(address=address, size=_parse_size(size))
        result = run_use_case(
            executor, lambda: get_bytes_use_case.execute(command)
        )
        return get_bytes_view(result.read)
