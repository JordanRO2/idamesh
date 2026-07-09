"""IDA adapter implementing :class:`~idamesh.domain.ports.snapshot.SnapshotGateway`.

The SDK seam is implemented below; this module is a lazy-import skeleton so
the worker container can register ``idb_snapshot`` and the package stays importable
with no IDA present (the ``ida_*`` import happens inside the method).

Intended SDK call (the ``[merger]`` snapshot path): ``ida_loader.save_database(path,
ida_loader.DBFL_COMP)`` — the ``DBFL_COMP`` flag writes a compressed ``.i64`` and
the **absence** of ``DBFL_KILL`` means the live database and its loose working
files survive the save. On success, stat the written file for its size and return a
:class:`~idamesh.domain.entities.snapshot.Snapshot`; a refused save raises (surfaced
by the caller as an ``isError`` result).
"""

from __future__ import annotations

from idamesh.domain.entities.snapshot import Snapshot


class IdaSnapshotGateway:
    """:class:`~idamesh.domain.ports.snapshot.SnapshotGateway` over the IDA SDK."""

    def save(self, path: str) -> Snapshot:
        """Save a compressed ``.i64`` snapshot of the open database to ``path``.

        Delegates to ``ida_loader.save_database(path, DBFL_COMP)``: the
        ``DBFL_COMP`` flag compresses the written database, and the deliberate
        absence of ``DBFL_KILL`` means the live database and its loose working
        files (``.id0``/``.id1``/``.nam``/``.til``) survive untouched, so the
        session stays open and editable after the snapshot. A save the kernel
        refuses — or a destination that cannot be written — raises, which the
        caller renders as an ``isError`` result. On success the written file is
        stat'd for its byte size.
        """
        import os

        import ida_loader

        # Compress the snapshot; never DBFL_KILL — the live working files stay.
        flags = getattr(ida_loader, "DBFL_COMP", 0x02)
        result = ida_loader.save_database(path, flags)
        # ``save_database`` returns a truthy value (or ``None`` on the SDK builds
        # that type it as void) on success and a falsy value on a refused save.
        if result is False or result == 0:
            raise RuntimeError(
                f"IDA refused to save the database snapshot to {path!r}"
            )
        try:
            size = os.path.getsize(path)
        except OSError as exc:
            raise RuntimeError(
                f"database snapshot to {path!r} left no readable file: {exc}"
            ) from exc
        return Snapshot(path=path, size=int(size))
