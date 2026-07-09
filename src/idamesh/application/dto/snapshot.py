"""Command/Result DTOs for the ``idb_snapshot`` tool.

``SnapshotCommand`` carries the destination path; ``SnapshotResult`` wraps the
resulting :class:`~idamesh.domain.entities.snapshot.Snapshot`. Path validation
(non-empty) happens in the use-case before the gateway is asked to write.
"""

from __future__ import annotations

from dataclasses import dataclass

from idamesh.domain.entities.snapshot import Snapshot


@dataclass(frozen=True)
class SnapshotCommand:
    """Input for ``idb_snapshot`` — the destination ``.i64`` path to write."""

    path: str


@dataclass(frozen=True)
class SnapshotResult:
    """Output for ``idb_snapshot`` — the written snapshot."""

    snapshot: Snapshot
