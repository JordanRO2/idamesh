"""Catalog registration + wire projection for ``idb_snapshot``.

The ``SnapshotView`` ``TypedDict`` gives the schema compiler an object-rooted
``outputSchema``; :func:`snapshot_view` renders the completed save into the flat
``{path, ok, size}`` shape (``ok`` always true on success — a refused save comes
back as an ``isError`` result instead). The tool is marked ``@registry.mutating``
because it writes a file and needs write affinity on the kernel thread, though it
never disturbs the live database.
"""

from __future__ import annotations

from typing import TypedDict

from idamesh.application.contexts.snapshot import SnapshotUseCase
from idamesh.application.dto.snapshot import SnapshotCommand
from idamesh.domain.entities.snapshot import Snapshot
from idamesh.domain.ports.execution import MainThreadExecutor
from idamesh.interface.catalog._support import run_mutation
from idamesh.interface.mcp.registry import Registry


class SnapshotView(TypedDict):
    """The outcome of one ``idb_snapshot`` call."""

    path: str
    ok: bool
    size: int


def snapshot_view(snapshot: Snapshot) -> SnapshotView:
    """Project a :class:`Snapshot` into its wire shape."""
    return SnapshotView(path=snapshot.path, ok=True, size=snapshot.size)


def register_idb_snapshot(
    registry: Registry,
    *,
    snapshot_use_case: SnapshotUseCase,
    executor: MainThreadExecutor,
) -> None:
    """Register ``idb_snapshot`` (mutating) against the snapshot use-case."""

    @registry.tool(name="idb_snapshot")
    @registry.mutating
    def idb_snapshot(path: str) -> SnapshotView:
        """Save a compressed ``.i64`` snapshot of this database to ``path``. Writes
        a compressed copy to the given destination without disturbing the live
        database or its loose working files, so a session stays open and editable
        after the snapshot. The result reports the destination ``path``, ``ok``,
        and the written file ``size`` in bytes. This writes a file (but does not
        modify the open database). A destination that cannot be written, or a save
        the database refuses, yields an error result rather than failing the
        protocol request."""
        command = SnapshotCommand(path=path)
        result = run_mutation(
            executor, lambda: snapshot_use_case.execute(command)
        )
        return snapshot_view(result.snapshot)
