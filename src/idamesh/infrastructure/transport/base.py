"""The transport ABC and the dispatcher seam it drives.

A transport's only jobs are framing, per-connection concerns (headers, sessions,
SSE), and gathering the raw request-context fields; it never knows what a tool
is. It drives a :class:`Dispatcher` — structurally the ``infrastructure.rpc``
``Router`` — passing primitives only, so no transport imports the engine.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional, Protocol, Union


class Dispatcher(Protocol):
    """What a transport calls to turn request bytes into reply bytes."""

    def dispatch(
        self,
        raw: Union[bytes, str],
        *,
        session_id: Optional[str] = None,
        protocol_version: Optional[str] = None,
        features: frozenset = frozenset(),
        deadline: Optional[float] = None,
    ) -> Optional[bytes]:
        """Return the encoded reply, or ``None`` for a notification/response-only input."""
        ...


class Transport(ABC):
    """Base class for the concrete transports (stdio, streamable HTTP)."""

    def __init__(self, dispatcher: Dispatcher) -> None:
        self._dispatcher = dispatcher

    @abstractmethod
    def serve(self, *, block: bool = True) -> None:
        """Begin serving. ``block=True`` runs in the foreground until stopped."""
        ...

    @abstractmethod
    def stop(self) -> None:
        """Stop serving and release the underlying resource (socket/pipe)."""
        ...
