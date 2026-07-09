"""Templated struct resource keyed by type name.

One URI template — ``ida://struct/{name}`` — exposes a named type's full
definition (its kind, byte size, and member layout) as a browsable MCP resource,
backed by :class:`~idamesh.application.contexts.types.TypeInspectUseCase` and
reusing the ``type_inspect`` tool's wire projection verbatim.

Following the canonical template pattern (``resources/raw_bytes.py``): the engine
matches the concrete URI with a per-template regex, so ``{name}`` captures one
path segment and arrives as a string — the type's name, handed straight to the
command. The use-case is marshalled onto the kernel thread through
:func:`run_use_case`, so an unknown type name is raised as a ``ToolError`` that
the engine renders as a ``resources/read`` resource-not-found error rather than a
tool ``isError`` envelope.
"""

from __future__ import annotations

from idamesh.application.contexts.types import TypeInspectUseCase
from idamesh.application.dto.types import TypeInspectCommand
from idamesh.domain.ports.execution import MainThreadExecutor
from idamesh.interface.catalog.resources._support import run_use_case
from idamesh.interface.catalog.type_inspect import TypeInspectView, type_inspect_view
from idamesh.interface.mcp.registry import Registry

#: The URI template of the struct/type-definition resource.
STRUCT_URI_TEMPLATE = "ida://struct/{name}"


def register_struct_resources(
    registry: Registry,
    *,
    type_inspect_use_case: TypeInspectUseCase,
    executor: MainThreadExecutor,
) -> None:
    """Register the ``ida://struct/{name}`` template against the type-inspect use-case."""

    @registry.resource(STRUCT_URI_TEMPLATE, name="struct")
    def struct(name: str) -> TypeInspectView:
        """Resolve the type named ``name`` from the database's local type catalog
        and offer its full definition as a browsable resource. ``name`` is a URI
        path segment — the type's name. The payload reports the type's ``name``,
        its coarse ``kind`` (struct / union / enum / typedef / pointer / …), its
        byte ``size``, and its ``members`` — one row per field with the member
        ``name``, rendered ``type``, byte ``offset``, and ``size`` — identical to
        the ``type_inspect`` tool (``members`` is empty for non-aggregate types).
        A name no type binds to yields a resource-not-found error."""
        command = TypeInspectCommand(name=name)
        result = run_use_case(
            executor, lambda: type_inspect_use_case.execute(command)
        )
        return type_inspect_view(result.type_info)
