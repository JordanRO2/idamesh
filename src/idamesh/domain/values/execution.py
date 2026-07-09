"""Pure execution value objects: :class:`Deadline` and :class:`CancelScope`.

These model the *time* and *cancellation* facts a running tool must honor,
without any IDA or threading-primitive dependency of their own. The scope
aggregates the three independent stop signals (wall-clock expiry, client
cancellation, host shutdown) behind one cooperative surface a tool body polls;
the concrete signal sources are supplied as plain callables so the object stays
unit-testable on synthetic clocks.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Optional


class CancelReason(Enum):
    """Why a :class:`CancelScope` reports that work should stop."""

    TIMEOUT = "timeout"
    CLIENT = "client"
    HOST = "host"


class ScopeCancelled(Exception):
    """Raised by :meth:`CancelScope.check` when the scope demands a stop.

    The concrete :class:`CancelReason` that tripped is carried on ``reason`` so a
    higher layer can map it onto the runtime error taxonomy (a timeout renders as
    a tool error; a client cancellation renders as a cancellation, not a failure).
    """

    def __init__(self, reason: CancelReason, message: Optional[str] = None) -> None:
        self.reason = reason
        super().__init__(message if message is not None else reason.value)


def _clock(now: Optional[float]) -> float:
    """Resolve an explicit synthetic ``now`` or fall back to the monotonic clock."""
    return now if now is not None else time.monotonic()


@dataclass(frozen=True)
class Deadline:
    """A monotonic-clock deadline; ``at is None`` means unbounded."""

    at: Optional[float] = None

    @classmethod
    def after(cls, seconds: Optional[float], *, now: Optional[float] = None) -> "Deadline":
        """A deadline ``seconds`` from ``now`` (monotonic). ``None``/``<= 0``
        seconds yields an unbounded deadline."""
        if seconds is None or seconds <= 0:
            return cls(None)
        return cls(_clock(now) + seconds)

    @classmethod
    def none(cls) -> "Deadline":
        """An explicitly unbounded deadline."""
        return cls(None)

    def expired(self, *, now: Optional[float] = None) -> bool:
        """``True`` once the monotonic clock has reached the deadline."""
        if self.at is None:
            return False
        return _clock(now) >= self.at

    def remaining(self, *, now: Optional[float] = None) -> Optional[float]:
        """Seconds left (never negative), or ``None`` when unbounded."""
        if self.at is None:
            return None
        return max(0.0, self.at - _clock(now))


class CancelScope:
    """Cooperative cancellation surface unifying the three stop signals.

    The scope is created on the submitting side and consulted from the running
    job. ``should_stop`` folds the wall-clock deadline together with the injected
    client- and host-cancellation predicates; ``check`` is the raising backstop.
    """

    def __init__(
        self,
        deadline: Optional[Deadline] = None,
        *,
        client_cancelled: Optional[Callable[[], bool]] = None,
        host_stopping: Optional[Callable[[], bool]] = None,
    ) -> None:
        self._deadline = deadline
        self._client_cancelled = client_cancelled
        self._host_stopping = host_stopping
        self._fired_at: Optional[float] = None

    @property
    def deadline(self) -> Optional[Deadline]:
        """The wall-clock deadline governing this scope, if any."""
        return self._deadline

    @property
    def fired_at(self) -> Optional[float]:
        """Monotonic instant the native cancel was tripped, else ``None``."""
        return self._fired_at

    def mark_fired(self, *, now: Optional[float] = None) -> None:
        """Record that the native cancel signal has been raised (starts the grace window)."""
        if self._fired_at is None:
            self._fired_at = _clock(now)

    def _client_wants_stop(self) -> bool:
        return bool(self._client_cancelled()) if self._client_cancelled is not None else False

    def _host_wants_stop(self) -> bool:
        return bool(self._host_stopping()) if self._host_stopping is not None else False

    def should_stop(self, *, now: Optional[float] = None) -> bool:
        """``True`` if the deadline elapsed, the client cancelled, or the host is stopping."""
        return self.reason(now=now) is not None

    def reason(self, *, now: Optional[float] = None) -> Optional[CancelReason]:
        """Which signal is currently asserting a stop, or ``None``.

        Client intent outranks host shutdown, which outranks the wall clock — the
        same precedence the runtime tripwire applies when it converts a signal
        into a raised exception.
        """
        if self._client_wants_stop():
            return CancelReason.CLIENT
        if self._host_wants_stop():
            return CancelReason.HOST
        if self._deadline is not None and self._deadline.expired(now=now):
            return CancelReason.TIMEOUT
        return None

    def time_left(self, *, now: Optional[float] = None) -> Optional[float]:
        """Convenience: seconds remaining on the deadline, or ``None``."""
        if self._deadline is None:
            return None
        return self._deadline.remaining(now=now)

    def check(self, *, now: Optional[float] = None) -> None:
        """Raise the appropriate cancellation/timeout error if work must stop."""
        reason = self.reason(now=now)
        if reason is not None:
            raise ScopeCancelled(reason)
