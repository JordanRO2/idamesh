"""The snapshot entity: a saved compressed database file.

``idb_snapshot`` writes a compressed ``.i64`` copy of the open database to an
explicit path without disturbing the live working files. :class:`Snapshot` is the
record of that write — the destination ``path`` and the resulting file ``size`` in
bytes — from which the tool's ``{path, ok, size}`` result is projected. The field
set is the interoperability fact; the projection is the interface layer's.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Snapshot:
    """A saved database snapshot: where it was written and how large it is."""

    #: Absolute or caller-supplied destination path of the written ``.i64``.
    path: str
    #: Size of the written file in bytes.
    size: int
