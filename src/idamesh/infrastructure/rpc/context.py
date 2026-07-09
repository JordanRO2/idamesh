"""Per-request context and cooperative cancellation.

One immutable :class:`RequestContext` is bound on a ``contextvars.ContextVar``
for the duration of a dispatch, so leaf code reads request state without it
being threaded through every call. Cancellation is an *object per request*: the
:class:`CancellationRegistry` maps a live request id to a :class:`CancellationToken`
that a client ``notifications/cancelled`` trips and a long tool polls.

The concrete :class:`RequestContext` / :class:`CancellationToken` here
structurally satisfy the interface-layer ``RequestView`` / ``CancelSignal``
protocols, so the engine consumes them without importing this module.
"""

from __future__ import annotations

import contextvars
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator, Optional, Union

#: JSON-RPC id domain (fractional numbers are rejected upstream).
RpcId = Union[str, int, None]


class Cancelled(Exception):
    """Raised by :meth:`CancellationToken.check` when a request was cancelled."""


class CancellationToken:
    """A one-shot cooperative cancellation flag backed by a ``threading.Event``."""

    def __init__(self) -> None:
        self._event = threading.Event()

    @property
    def cancelled(self) -> bool:
        """``True`` once :meth:`cancel` has been called."""
        return self._event.is_set()

    def cancel(self) -> None:
        """Trip the flag (thread-safe)."""
        self._event.set()

    def check(self) -> None:
        """Raise :class:`Cancelled` if tripped; otherwise return."""
        if self._event.is_set():
            raise Cancelled("request cancelled")


@dataclass(frozen=True)
class RequestContext:
    """Immutable per-request state bound for the duration of one dispatch."""

    request_id: RpcId
    session_id: Optional[str]
    protocol_version: str
    features: frozenset
    cancel: CancellationToken
    deadline: Optional[float] = None


class CancellationRegistry:
    """Maps in-flight request ids to their cancellation tokens, under a lock."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._tokens: "dict[RpcId, CancellationToken]" = {}

    def open(self, request_id: RpcId) -> CancellationToken:
        """Create and register a token for ``request_id``."""
        token = CancellationToken()
        with self._lock:
            self._tokens[request_id] = token
        return token

    def close(self, request_id: RpcId) -> None:
        """Drop the token for ``request_id`` (idempotent)."""
        with self._lock:
            self._tokens.pop(request_id, None)

    def trip(self, request_id: RpcId) -> bool:
        """Cancel the token for ``request_id``; ``True`` if one was live."""
        with self._lock:
            token = self._tokens.get(request_id)
        if token is None:
            return False
        token.cancel()
        return True


_ctx: "contextvars.ContextVar[Optional[RequestContext]]" = contextvars.ContextVar(
    "idamesh_request_ctx", default=None
)


def current() -> Optional[RequestContext]:
    """The context bound to the current dispatch, or ``None``."""
    return _ctx.get()


@contextmanager
def bind(ctx: RequestContext) -> Iterator[None]:
    """Bind ``ctx`` for the enclosed block, restoring the prior value on exit."""
    token = _ctx.set(ctx)
    try:
        yield
    finally:
        _ctx.reset(token)
