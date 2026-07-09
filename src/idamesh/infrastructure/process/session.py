"""The worker-session record and its backend tag (orchestrator-side, idapro-free).

A :class:`WorkerSession` is the single routing record the supervisor keeps for one
open database: the immutable identity (``session_id``, the user's ``input_path``,
the per-session ``private_copy_path`` that was actually opened) plus the live
endpoint (``host``/``port``) and the OS process handle needed to health-check and
reap it. It is deliberately a plain, mutable dataclass with no IDA and no network
knowledge — the pool fills the endpoint/process fields in after the worker has
spawned and reported its bound port, and :meth:`touch` records last use.

This module imports only the standard library, so it is safe in the supervisor
process (which must never load ``idapro``).
"""

from __future__ import annotations

import enum
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping, Optional


def _utc_now_iso() -> str:
    """An ISO-8601 UTC timestamp (used for ``created_at`` / ``last_accessed``)."""
    return datetime.now(timezone.utc).isoformat()


class Backend(str, enum.Enum):
    """How a session's database is hosted.

    The string values match the ``backend`` field the filesystem discovery
    registry advertises, so a record round-trips without translation.
    """

    #: A headless ``idalib`` worker the supervisor spawned and may reap.
    HEADLESS_WORKER = "worker"
    #: A live interactive IDA GUI the supervisor adopted (never reaped).
    ADOPTED_GUI = "gui"


@dataclass
class WorkerSession:
    """One routable open database behind the supervisor.

    Identity is set at mint time; the endpoint (``host``/``port``), ``process``
    handle, and optional ``token`` are populated by the pool once the worker has
    bound its socket and emitted its readiness handshake.
    """

    session_id: str
    #: The path the user asked to open (never opened directly under N-copies).
    input_path: str
    #: The per-session private copy actually handed to the worker (or ``""`` for
    #: an adopted GUI, which owns its own database).
    private_copy_path: str
    host: str
    port: int
    backend: Backend = Backend.HEADLESS_WORKER
    created_at: str = field(default_factory=_utc_now_iso)
    last_accessed: str = field(default_factory=_utc_now_iso)
    #: OS process handle for an owned worker (``subprocess.Popen``); ``None`` for
    #: an adopted GUI or before spawn completes. Typed loosely to keep this
    #: module free of a ``subprocess`` import in its annotations.
    process: Optional[Any] = None
    #: Bearer token to present when forwarding to this session, if it enforces one.
    token: Optional[str] = None
    #: The session's pristine annotation export (the frozen ``AnnotationRecordWire``
    #: document), captured in-process right after the worker became ready and its
    #: initial auto-analysis finished — **before** any agent edit. ``idb_merge``
    #: subtracts this from the session's current export so only that session's real
    #: edits remain, with zero cross-copy analysis variance (a separately spawned
    #: baseline is a different idalib process and is not bit-identical). ``None``
    #: until captured, or when the capture export failed (merge falls back safely).
    baseline_record: Optional[Mapping[str, Any]] = None
    #: Free-form extras (image base, ida version, warmup snapshot, …).
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @property
    def filename(self) -> str:
        """The basename of the user's input path, for display in listings."""
        return os.path.basename(self.input_path)

    def touch(self) -> None:
        """Record that the session was just used (updates ``last_accessed``)."""
        self.last_accessed = _utc_now_iso()

    def to_info(self) -> dict:
        """The public, JSON-safe session descriptor returned by the management
        tools (``idb_open`` / ``idb_list``)."""
        return {
            "session_id": self.session_id,
            "input_path": self.input_path,
            "filename": self.filename,
            "private_copy_path": self.private_copy_path,
            "backend": self.backend.value,
            "host": self.host,
            "port": self.port,
            "created_at": self.created_at,
            "last_accessed": self.last_accessed,
        }
