"""Catalog registrations for the core context: ``get_metadata`` + ``server_health``."""

from __future__ import annotations

from idamesh.application.contexts.core import (
    GetMetadataUseCase,
    ServerHealthUseCase,
)
from idamesh.application.dto.core import GetMetadataCommand, ServerHealthCommand
from idamesh.domain.ports.execution import MainThreadExecutor
from idamesh.interface.catalog._support import run_use_case
from idamesh.interface.catalog.views import (
    HealthView,
    MetadataView,
    health_view,
    metadata_view,
)
from idamesh.interface.mcp.registry import Registry


def register_core(
    registry: Registry,
    *,
    metadata_use_case: GetMetadataUseCase,
    health_use_case: ServerHealthUseCase,
    executor: MainThreadExecutor,
) -> None:
    """Register ``get_metadata`` and ``server_health`` against the core use-cases."""

    @registry.tool(name="get_metadata")
    def get_metadata() -> MetadataView:
        """Describe the loaded database: input file identity, processor and
        bitness, byte order, entry point and image base, and coarse counts of
        functions and segments. Call this first to orient on an unfamiliar
        target before enumerating or decompiling anything."""
        result = run_use_case(
            executor, lambda: metadata_use_case.execute(GetMetadataCommand())
        )
        return metadata_view(result.metadata)

    @registry.tool(name="server_health")
    def server_health() -> HealthView:
        """Report server liveness and whether a database is currently bound and
        ready to serve reads, along with the server version and the MCP protocol
        revisions this endpoint can negotiate. Safe to poll at any time."""
        result = run_use_case(
            executor, lambda: health_use_case.execute(ServerHealthCommand())
        )
        return health_view(result.health)
