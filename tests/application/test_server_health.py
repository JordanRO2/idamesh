"""server_health reports the open .i64 location, not the input-binary path.

The two differ whenever an IDB is moved after creation: ``get_input_file_path``
keeps the original executable's path, while the database lives elsewhere.
"""

from __future__ import annotations

from idamesh.application.contexts.core import ServerHealthUseCase
from idamesh.application.dto.core import ServerHealthCommand
from idamesh.domain.entities.metadata import DatabaseMetadata, Endianness


class _Database:
    def __init__(self, metadata: DatabaseMetadata) -> None:
        self._metadata = metadata

    def is_open(self) -> bool:
        return True

    def metadata(self) -> DatabaseMetadata:
        return self._metadata


def _metadata(**kw) -> DatabaseMetadata:
    return DatabaseMetadata(
        path="I:/old/target.exe",
        module="target.exe",
        architecture="metapc",
        bits=64,
        endianness=Endianness.LITTLE,
        **kw,
    )


def test_health_reports_idb_location_not_input_path():
    db = _Database(_metadata(idb_path="C:/moved/target.exe.i64"))
    health = ServerHealthUseCase(db).execute(ServerHealthCommand()).health
    assert health.idb_path == "C:/moved/target.exe.i64"


def test_health_idb_path_none_when_unknown():
    health = ServerHealthUseCase(_Database(_metadata())).execute(ServerHealthCommand()).health
    assert health.idb_path is None
