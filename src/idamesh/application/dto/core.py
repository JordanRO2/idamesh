"""Command/Result DTOs for the core context: metadata and health."""

from __future__ import annotations

from dataclasses import dataclass

from idamesh.domain.entities.metadata import DatabaseMetadata, HealthStatus


@dataclass(frozen=True)
class GetMetadataCommand:
    """Input for ``get_metadata`` — takes no parameters."""


@dataclass(frozen=True)
class GetMetadataResult:
    """Output for ``get_metadata``."""

    metadata: DatabaseMetadata


@dataclass(frozen=True)
class ServerHealthCommand:
    """Input for ``server_health`` — takes no parameters."""


@dataclass(frozen=True)
class ServerHealthResult:
    """Output for ``server_health``."""

    health: HealthStatus
