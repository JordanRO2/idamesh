"""Core-context use-cases: get_metadata and server_health.

A use-case takes its outbound ports at construction and exposes ``execute(cmd)
-> result``. It assumes it is already running on the kernel thread — the
interface layer arranges that via the main-thread executor before calling.
Bodies land in the integration phase.
"""

from __future__ import annotations

from idamesh.application.dto.core import (
    GetMetadataCommand,
    GetMetadataResult,
    ServerHealthCommand,
    ServerHealthResult,
)
from idamesh.domain.entities.metadata import HealthStatus
from idamesh.domain.ports.database import DatabaseGateway


class GetMetadataUseCase:
    """Return descriptive facts about the open database."""

    def __init__(self, database: DatabaseGateway) -> None:
        self._database = database

    def execute(self, command: GetMetadataCommand) -> GetMetadataResult:
        return GetMetadataResult(metadata=self._database.metadata())


class ServerHealthUseCase:
    """Report server liveness/readiness (the ping-style probe).

    ``database`` is optional so the probe can answer even before a database is
    bound; when present it reports whether one is open.
    """

    def __init__(
        self,
        database: DatabaseGateway | None = None,
        *,
        server_version: str = "0.0.1",
        protocol_versions: tuple[str, ...] = (),
    ) -> None:
        self._database = database
        self._server_version = server_version
        self._protocol_versions = protocol_versions

    def execute(self, command: ServerHealthCommand) -> ServerHealthResult:
        database_open = False
        idb_path: str | None = None
        if self._database is not None:
            try:
                database_open = self._database.is_open()
            except Exception:
                database_open = False
            if database_open:
                try:
                    idb_path = self._database.metadata().path or None
                except Exception:
                    idb_path = None
        health = HealthStatus(
            ok=True,
            database_open=database_open,
            server_version=self._server_version,
            protocol_versions=self._protocol_versions,
            idb_path=idb_path,
            uptime_s=None,
        )
        return ServerHealthResult(health=health)
