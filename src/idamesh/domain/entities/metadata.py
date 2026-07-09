"""Database-level entities: :class:`DatabaseMetadata` and :class:`HealthStatus`.

``DatabaseMetadata`` is the payload of the ``get_metadata`` tool; ``HealthStatus``
backs the ``server_health``/ping surface. Both are plain immutable records whose
field set is the interoperability fact.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from idamesh.domain.values.address import Address


class Endianness(Enum):
    """Byte order of the analyzed image."""

    LITTLE = "little"
    BIG = "big"


@dataclass(frozen=True)
class DatabaseMetadata:
    """Descriptive facts about the currently open database."""

    path: str
    module: str
    architecture: str
    bits: int
    endianness: Endianness
    entrypoint: Address | None = None
    image_base: Address | None = None
    function_count: int = 0
    segment_count: int = 0
    string_count: int | None = None
    compiler: str | None = None
    filetype: str | None = None
    sha256: str | None = None


@dataclass(frozen=True)
class HealthStatus:
    """Liveness/readiness of the server and its database binding."""

    ok: bool
    database_open: bool
    server_version: str
    protocol_versions: tuple[str, ...]
    idb_path: str | None = None
    uptime_s: float | None = None
