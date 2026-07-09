"""In-memory fakes for driving the MCP engine without IDA or a transport.

These stand in for ``infrastructure.rpc.context.RequestContext`` /
``CancellationToken`` (which are area-C code, not built here). ``FakeCtx``
structurally satisfies the interface-layer ``RequestView`` protocol, and
``FakeCancel`` satisfies ``CancelSignal`` — so a tool can poll cancellation the
same way it would against the real token.
"""

from __future__ import annotations

from typing import Iterable, Optional


class FakeCancelled(Exception):
    """Raised by :meth:`FakeCancel.check` once the token is tripped."""


class FakeCancel:
    """A cooperative cancellation flag mirroring the real ``CancellationToken``."""

    def __init__(self, cancelled: bool = False) -> None:
        self._cancelled = cancelled

    @property
    def cancelled(self) -> bool:
        return self._cancelled

    def cancel(self) -> None:
        self._cancelled = True

    def check(self) -> None:
        if self._cancelled:
            raise FakeCancelled("request cancelled")


class FakeCtx:
    """A ``RequestView``-shaped per-request context for tests."""

    def __init__(
        self,
        *,
        features: Iterable[str] = (),
        cancel: Optional[FakeCancel] = None,
        protocol_version: str = "2025-11-25",
        request_id: object = 1,
        session_id: Optional[str] = "test-session",
        deadline: Optional[float] = None,
    ) -> None:
        self.request_id = request_id
        self.session_id = session_id
        self.protocol_version = protocol_version
        self.features = frozenset(features)
        self.deadline = deadline
        self.cancel = cancel if cancel is not None else FakeCancel()
