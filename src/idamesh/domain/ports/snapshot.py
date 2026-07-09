"""The snapshot gateway port: save a compressed database copy.

One port serves the ``idb_snapshot`` worker tool. :meth:`save` writes a compressed
``.i64`` snapshot of the currently open database to an explicit destination and
returns a :class:`~idamesh.domain.entities.snapshot.Snapshot` describing it. The
contract is deliberately non-destructive: it saves a *copy* to ``path`` (SDK
``DBFL_COMP``, **never** ``DBFL_KILL``), so the live working files that back the
session are never disturbed — the merge-back writes a canonical database while the
parallel copies stay open. A write the database refuses raises, surfaced by the
caller as an ``isError`` result. The adapter owns the SDK call.
"""

from __future__ import annotations

from typing import Protocol

from idamesh.domain.entities.snapshot import Snapshot


class SnapshotGateway(Protocol):
    """Write-side access that saves a compressed copy of the open database."""

    def save(self, path: str) -> Snapshot:
        """Save a compressed ``.i64`` snapshot of the open database to ``path``.

        The open database and its loose working files are left intact — this saves
        a *copy* to ``path``, it does not pack-and-close. Returns a
        :class:`Snapshot` with the destination path and the written file's size.
        Raises an error (surfaced by the caller as an ``isError`` result) when the
        save is refused or the destination cannot be written.
        """
        ...
