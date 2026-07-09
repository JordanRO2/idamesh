"""The ``ida://…`` resource catalog: read-only IDB state as MCP resources.

Resources reuse the *same* application use-cases the tool catalog binds — each
handler runs the relevant use-case (executor-marshalled, exactly like a tool)
and returns its JSON-native view, which the engine wraps as
``{ contents: [ { uri, mimeType: "application/json", text } ] }``. No new domain
code: resources are a second projection of the existing reads.

:func:`register_resources` is the single aggregator the composition root calls,
alongside :func:`idamesh.interface.catalog.register_slice` for tools. It fans out
to the per-owner registrars:

* :func:`register_metadata_resource` — ``ida://metadata`` (reference static)
* :func:`register_bytes_resource` — ``ida://bytes/{address}/{size}`` (reference template)
* :func:`register_static_resources` — ``ida://functions|globals|imports|strings``
* :func:`register_code_resources` — ``ida://function|disasm|xrefs/{address}``
* :func:`register_struct_resources` — ``ida://struct/{name}``
"""

from __future__ import annotations

from idamesh.application.contexts.core import GetMetadataUseCase
from idamesh.application.contexts.decompiler import DecompileUseCase
from idamesh.application.contexts.disasm import DisasmUseCase
from idamesh.application.contexts.functions import ListFuncsUseCase
from idamesh.application.contexts.globals import ListGlobalsUseCase
from idamesh.application.contexts.imports import ListImportsUseCase
from idamesh.application.contexts.list_strings import ListStringsUseCase
from idamesh.application.contexts.memory import GetBytesUseCase
from idamesh.application.contexts.types import TypeInspectUseCase
from idamesh.application.contexts.xrefs import XrefsToUseCase
from idamesh.domain.ports.execution import MainThreadExecutor
from idamesh.interface.catalog.resources.code import register_code_resources
from idamesh.interface.catalog.resources.metadata import register_metadata_resource
from idamesh.interface.catalog.resources.raw_bytes import register_bytes_resource
from idamesh.interface.catalog.resources.static import register_static_resources
from idamesh.interface.catalog.resources.structs import register_struct_resources
from idamesh.interface.mcp.registry import Registry

__all__ = [
    "register_metadata_resource",
    "register_bytes_resource",
    "register_static_resources",
    "register_code_resources",
    "register_struct_resources",
    "register_resources",
]


def register_resources(
    registry: Registry,
    *,
    metadata_use_case: GetMetadataUseCase,
    get_bytes_use_case: GetBytesUseCase,
    list_funcs_use_case: ListFuncsUseCase,
    list_globals_use_case: ListGlobalsUseCase,
    list_imports_use_case: ListImportsUseCase,
    list_strings_use_case: ListStringsUseCase,
    decompile_use_case: DecompileUseCase,
    disasm_use_case: DisasmUseCase,
    xrefs_to_use_case: XrefsToUseCase,
    type_inspect_use_case: TypeInspectUseCase,
    executor: MainThreadExecutor,
) -> None:
    """Register all ten ``ida://…`` resources onto ``registry``.

    Reuses the same use-cases the tool catalog binds; called by the composition
    root after :func:`idamesh.interface.catalog.register_slice`.
    """
    register_metadata_resource(
        registry,
        metadata_use_case=metadata_use_case,
        executor=executor,
    )
    register_bytes_resource(
        registry,
        get_bytes_use_case=get_bytes_use_case,
        executor=executor,
    )
    register_static_resources(
        registry,
        list_funcs_use_case=list_funcs_use_case,
        list_globals_use_case=list_globals_use_case,
        list_imports_use_case=list_imports_use_case,
        list_strings_use_case=list_strings_use_case,
        executor=executor,
    )
    register_code_resources(
        registry,
        decompile_use_case=decompile_use_case,
        disasm_use_case=disasm_use_case,
        xrefs_to_use_case=xrefs_to_use_case,
        executor=executor,
    )
    register_struct_resources(
        registry,
        type_inspect_use_case=type_inspect_use_case,
        executor=executor,
    )
