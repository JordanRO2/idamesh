"""Outbound ports the supervisor router depends on (interface-local).

The router lives in the ``interface`` layer, which may not import
``infrastructure``. So it programs against these small ``Protocol``s instead; the
composition root injects the concrete ``infrastructure.process.WorkerPool`` and
``infrastructure.rpc.WorkerClient``, which satisfy them structurally. This keeps
the layer boundary (and the idapro-free guarantee) a compile-time fact rather than
a convention.
"""

from __future__ import annotations

from typing import Any, Mapping, Optional, Protocol, Sequence, runtime_checkable


@runtime_checkable
class SessionView(Protocol):
    """The read surface the router needs from one worker session."""

    session_id: str
    input_path: str
    host: str
    port: int
    token: Optional[str]
    #: The session's pristine annotation export (a frozen ``AnnotationRecordWire``
    #: dict), captured in-process at open before any edit; ``None`` until captured
    #: (or when the capture failed). ``idb_merge`` subtracts it per source.
    baseline_record: Optional[Mapping[str, Any]]

    def to_info(self) -> Mapping[str, Any]:
        """The JSON-safe public descriptor returned by the management tools."""
        ...

    def touch(self) -> None:
        """Record that the session was just used."""
        ...


@runtime_checkable
class WorkerPoolPort(Protocol):
    """What the router needs from the process pool to manage sessions."""

    def open_session(
        self, input_path: str, *, preferred_session_id: Optional[str] = None
    ) -> SessionView:
        """Open ``input_path``; mint a fresh private-copy worker unless a live
        ``preferred_session_id`` is given (then share it)."""
        ...

    def list_sessions(self) -> Sequence[SessionView]:
        """All live sessions in stable order."""
        ...

    def get(self, session_id: str) -> Optional[SessionView]:
        """The session for ``session_id`` or ``None`` if unknown/dead."""
        ...

    def close_session(self, session_id: str) -> bool:
        """Reap the worker and drop the session; ``True`` if one existed."""
        ...

    def reap(self) -> Sequence[str]:
        """Drop sessions whose worker died; return their ids."""
        ...


@runtime_checkable
class GuiDiscoveryPort(Protocol):
    """What the router needs to adopt live instances it did not spawn.

    Satisfied by the idapro-free filesystem-discovery reader the composition root
    injects (``infrastructure.discovery.GuiDiscoveryReader``). It surfaces the
    running GUI (and any other adopted-backend) instances as ``SessionView``
    records so the router can list them alongside its owned workers and forward a
    routed ``tools/call`` to them — read-only; the router never spawns or reaps an
    adopted instance. Optional: with no reader wired the supervisor simply exposes
    its owned workers.
    """

    def list_sessions(self) -> Sequence[SessionView]:
        """The live discovered instances, as routable sessions."""
        ...

    def get(self, session_id: str) -> Optional[SessionView]:
        """The live discovered instance named ``session_id``, or ``None``."""
        ...


@runtime_checkable
class WorkerClientPort(Protocol):
    """What the router needs to forward a frame to a worker and relay the reply."""

    def forward(
        self,
        *,
        host: str,
        port: int,
        frame: Mapping[str, Any],
        token: Optional[str] = None,
    ) -> Optional[Mapping[str, Any]]:
        """Forward one JSON-RPC frame; return the parsed response (or ``None``)."""
        ...

    def ping(self, *, host: str, port: int, token: Optional[str] = None) -> bool:
        """Health-check the endpoint with a real ``ping`` round-trip."""
        ...
