"""Reference **static** resource: ``ida://metadata`` (``GetMetadataUseCase``).

This is the canonical pattern the static-resource builder mirrors. A static
resource is a zero-argument handler registered under a fixed URI; the engine
matches the literal URI, invokes the handler on the kernel thread through
:func:`run_use_case`, and wraps the returned JSON-native view in
``{ contents: [ { uri, mimeType: "application/json", text } ] }``. The view is
the exact same projection the ``get_metadata`` tool returns, reused verbatim.
"""

from __future__ import annotations

from idamesh.application.contexts.core import GetMetadataUseCase
from idamesh.application.dto.core import GetMetadataCommand
from idamesh.domain.ports.execution import MainThreadExecutor
from idamesh.interface.catalog.resources._support import run_use_case
from idamesh.interface.catalog.views import MetadataView, metadata_view
from idamesh.interface.mcp.registry import Registry

#: The fixed URI of the database-metadata resource.
METADATA_URI = "ida://metadata"


def register_metadata_resource(
    registry: Registry,
    *,
    metadata_use_case: GetMetadataUseCase,
    executor: MainThreadExecutor,
) -> None:
    """Register ``ida://metadata`` against the metadata use-case."""

    @registry.resource(METADATA_URI, name="metadata")
    def metadata() -> MetadataView:
        """Describe the loaded database as a browsable resource: input file
        identity, processor and bitness, byte order, entry point and image base,
        and coarse function/segment counts. The same projection the
        ``get_metadata`` tool returns, offered as read-only state under the
        ``ida://metadata`` URI."""
        result = run_use_case(
            executor, lambda: metadata_use_case.execute(GetMetadataCommand())
        )
        return metadata_view(result.metadata)
