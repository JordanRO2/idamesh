"""Static resources: functions / globals / imports / strings.

Four zero-argument handlers registered under fixed ``ida://…`` URIs, mirroring
the reference static resource ``resources/metadata.py`` exactly: the engine
matches the literal URI, invokes the handler on the kernel thread through
:func:`run_use_case`, and wraps the returned JSON-native view in
``{ contents: [ { uri, mimeType: "application/json", text } ] }``. Each view is
the exact projection the equivalent listing tool returns, reused verbatim.

Each resource returns the *first page* of its listing (the use-case defaults:
``offset=0``, ``count=100``); deeper paging stays on the equivalent tool.
"""

from __future__ import annotations

from idamesh.application.contexts.functions import ListFuncsUseCase
from idamesh.application.contexts.globals import ListGlobalsUseCase
from idamesh.application.contexts.imports import ListImportsUseCase
from idamesh.application.contexts.list_strings import ListStringsUseCase
from idamesh.application.dto.functions import ListFuncsCommand
from idamesh.application.dto.globals import ListGlobalsCommand
from idamesh.application.dto.imports import ListImportsCommand
from idamesh.application.dto.list_strings import ListStringsCommand
from idamesh.domain.ports.execution import MainThreadExecutor
from idamesh.interface.catalog.imports import ListImportsView, list_imports_view
from idamesh.interface.catalog.list_strings import ListStringsView, list_strings_view
from idamesh.interface.catalog.resources._support import run_use_case
from idamesh.interface.catalog.views import (
    ListFuncsView,
    ListGlobalsView,
    list_funcs_view,
    list_globals_view,
)
from idamesh.interface.mcp.registry import Registry

#: The fixed URIs of the four static listing resources.
FUNCTIONS_URI = "ida://functions"
GLOBALS_URI = "ida://globals"
IMPORTS_URI = "ida://imports"
STRINGS_URI = "ida://strings"


def register_static_resources(
    registry: Registry,
    *,
    list_funcs_use_case: ListFuncsUseCase,
    list_globals_use_case: ListGlobalsUseCase,
    list_imports_use_case: ListImportsUseCase,
    list_strings_use_case: ListStringsUseCase,
    executor: MainThreadExecutor,
) -> None:
    """Register ``ida://functions|globals|imports|strings`` (first page each)."""

    @registry.resource(FUNCTIONS_URI, name="functions")
    def functions() -> ListFuncsView:
        """Enumerate the database's functions as a browsable resource: the first
        page in address order, each row carrying the function's name, entry and
        end address, size, and its library/thunk kind flags. The same projection
        the ``list_funcs`` tool returns, offered as read-only state under the
        ``ida://functions`` URI; deeper paging stays on the tool."""
        result = run_use_case(
            executor, lambda: list_funcs_use_case.execute(ListFuncsCommand())
        )
        return list_funcs_view(result.page)

    @registry.resource(GLOBALS_URI, name="globals")
    def globals_() -> ListGlobalsView:
        """Enumerate the database's named global (data) symbols as a browsable
        resource: the first page in address order, each row carrying the symbol's
        name, address, item size, and declared type when known. The same
        projection the ``list_globals`` tool returns, offered as read-only state
        under the ``ida://globals`` URI; deeper paging stays on the tool."""
        result = run_use_case(
            executor, lambda: list_globals_use_case.execute(ListGlobalsCommand())
        )
        return list_globals_view(result.page)

    @registry.resource(IMPORTS_URI, name="imports")
    def imports() -> ListImportsView:
        """Enumerate the module's imported symbols as a browsable resource: the
        first page grouped by originating library, each row carrying the symbol
        name, its import-table address, the module it is drawn from, and its
        ordinal when the platform links by ordinal. The same projection the
        ``imports`` tool returns, offered as read-only state under the
        ``ida://imports`` URI; deeper paging stays on the tool."""
        result = run_use_case(
            executor, lambda: list_imports_use_case.execute(ListImportsCommand())
        )
        return list_imports_view(result.page)

    @registry.resource(STRINGS_URI, name="strings")
    def strings() -> ListStringsView:
        """Enumerate the strings IDA extracted from the binary as a browsable
        resource: the first page in address order, each row carrying the string's
        address, byte length, encoding type, and decoded value. The same
        projection the ``list_strings`` tool returns, offered as read-only state
        under the ``ida://strings`` URI; deeper paging stays on the tool."""
        result = run_use_case(
            executor, lambda: list_strings_use_case.execute(ListStringsCommand())
        )
        return list_strings_view(result.page)
