"""Turn discovered instance records into routable supervisor sessions (idapro-free).

The supervisor routes ``tools/call`` against ``SessionView``-shaped records: a
``session_id`` and the ``host``/``port``/``token`` to forward to. An owned worker's
record is a :class:`~idamesh.infrastructure.process.session.WorkerSession`; an
*adopted* instance's record is a :class:`DiscoveredSession`, built here from a
:class:`~idamesh.infrastructure.discovery.registry.DiscoveryEntry`. Both satisfy the
router's ``SessionView`` protocol structurally, so forwarding to an adopted GUI is
identical to forwarding to a worker — only where the record comes from differs.

:class:`GuiDiscoveryReader` is the ``GuiDiscoveryPort`` the composition root injects
into the router: it surfaces the *live* discovered instances of the selected
backends (GUI by default) as sessions the router can list and address. It never
imports IDA and never spawns anything — adoption is read-only.
"""

from __future__ import annotations

import os
from typing import List, Mapping, Optional, Sequence

from idamesh.infrastructure.discovery.registry import (
    BACKEND_GUI,
    DiscoveryEntry,
    DiscoveryRegistry,
)


class DiscoveredSession:
    """A routing record for an adopted instance (satisfies the router's ``SessionView``).

    Adopted instances own their own database, so there is no private copy and no
    pristine baseline to subtract at merge time; ``touch`` is a no-op because the
    supervisor does not own the instance's lifecycle.
    """

    #: An adopted instance is never merge-sourced with a subtracted baseline.
    baseline_record: Optional[Mapping[str, object]] = None

    def __init__(self, entry: DiscoveryEntry) -> None:
        self._entry = entry
        self.session_id = entry.session_id
        self.host = entry.host
        self.port = entry.port
        self.token = entry.token
        # Prefer the concrete idb/binary path for display; fall back to the name.
        self.input_path = entry.idb_path or entry.binary or ""

    @property
    def backend(self) -> str:
        return self._entry.backend

    @property
    def filename(self) -> str:
        if self._entry.binary:
            return self._entry.binary
        return os.path.basename(self.input_path)

    def touch(self) -> None:
        """No-op: the supervisor does not own an adopted instance's lifecycle."""
        return None

    def to_info(self) -> dict:
        """The public session descriptor (same keys as an owned worker's)."""
        return {
            "session_id": self.session_id,
            "input_path": self.input_path,
            "filename": self.filename,
            "private_copy_path": "",
            "backend": self._entry.backend,
            "host": self.host,
            "port": self.port,
            "created_at": self._entry.started_at,
            "last_accessed": self._entry.started_at,
        }


class GuiDiscoveryReader:
    """Reads the registry and yields adopted sessions for the selected backends.

    Satisfies the router's ``GuiDiscoveryPort``. By default only ``gui`` records are
    adopted — the supervisor owns and tracks the headless workers it spawns itself,
    so it does not re-adopt ``worker`` records (which would double-count them).
    """

    def __init__(
        self,
        registry: Optional[DiscoveryRegistry] = None,
        *,
        backends: Sequence[str] = (BACKEND_GUI,),
    ) -> None:
        self._registry = registry or DiscoveryRegistry()
        self._backends = frozenset(backends)

    def list_sessions(self) -> List[DiscoveredSession]:
        """Every live discovered instance of an adopted backend, oldest-first."""
        return [
            DiscoveredSession(entry)
            for entry in self._registry.read_all()
            if entry.backend in self._backends
        ]

    def get(self, session_id: str) -> Optional[DiscoveredSession]:
        """The live discovered instance named ``session_id``, or ``None``."""
        entry = self._registry.find_by_session(session_id)
        if entry is None or entry.backend not in self._backends:
            return None
        return DiscoveredSession(entry)
