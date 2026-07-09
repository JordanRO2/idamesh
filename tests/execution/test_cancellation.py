"""Tests for the cooperative cancellation VOs: :class:`Deadline` and
:class:`CancelScope`.

Every assertion drives a *synthetic* ``now`` so the clock is deterministic and
the tests never race the real monotonic clock. We cover the wall-clock deadline
(expiry, remaining budget, unbounded cases), each of the three stop signals,
their precedence, the ``fired_at`` grace-window latch, and the raising backstop
``check``.
"""

from __future__ import annotations

import pytest

from idamesh.domain.values.execution import (
    CancelReason,
    CancelScope,
    Deadline,
    ScopeCancelled,
)


# --------------------------------------------------------------------------- #
# Deadline
# --------------------------------------------------------------------------- #

def test_deadline_after_sets_absolute_instant() -> None:
    dl = Deadline.after(10, now=100.0)

    assert dl.at == 110.0


def test_deadline_expired_transitions_at_the_instant() -> None:
    dl = Deadline.after(10, now=100.0)  # fires at 110

    assert dl.expired(now=109.999) is False
    assert dl.expired(now=110.0) is True   # reaching the instant counts as expired
    assert dl.expired(now=200.0) is True


def test_deadline_remaining_is_clamped_non_negative() -> None:
    dl = Deadline.after(10, now=100.0)

    assert dl.remaining(now=100.0) == 10.0
    assert dl.remaining(now=105.0) == 5.0
    assert dl.remaining(now=110.0) == 0.0
    assert dl.remaining(now=999.0) == 0.0  # never goes negative


@pytest.mark.parametrize("seconds", [None, 0, 0.0, -1, -99.0])
def test_deadline_none_or_nonpositive_is_unbounded(seconds: object) -> None:
    dl = Deadline.after(seconds, now=100.0)  # type: ignore[arg-type]

    assert dl.at is None
    assert dl.expired(now=1e18) is False
    assert dl.remaining(now=1e18) is None


def test_deadline_none_classmethod() -> None:
    dl = Deadline.none()

    assert dl.at is None
    assert dl.expired() is False
    assert dl.remaining() is None


def test_deadline_is_frozen() -> None:
    dl = Deadline.after(5, now=0.0)
    with pytest.raises(Exception):
        dl.at = 1.0  # type: ignore[misc]


# --------------------------------------------------------------------------- #
# CancelScope — quiescent
# --------------------------------------------------------------------------- #

def test_scope_without_signals_never_stops() -> None:
    scope = CancelScope()

    assert scope.should_stop() is False
    assert scope.reason() is None
    assert scope.deadline is None
    assert scope.fired_at is None
    assert scope.time_left() is None
    scope.check()  # must not raise


# --------------------------------------------------------------------------- #
# CancelScope — deadline (T) signal
# --------------------------------------------------------------------------- #

def test_scope_deadline_expiry_is_detectable() -> None:
    scope = CancelScope(Deadline.after(10, now=0.0))  # deadline at 10

    assert scope.should_stop(now=5.0) is False
    assert scope.reason(now=5.0) is None
    assert scope.time_left(now=5.0) == 5.0

    assert scope.should_stop(now=10.0) is True
    assert scope.reason(now=10.0) is CancelReason.TIMEOUT
    assert scope.time_left(now=10.0) == 0.0


def test_scope_check_raises_on_deadline() -> None:
    scope = CancelScope(Deadline.after(1, now=0.0))

    scope.check(now=0.5)  # before deadline: no raise
    with pytest.raises(ScopeCancelled) as excinfo:
        scope.check(now=2.0)
    assert excinfo.value.reason is CancelReason.TIMEOUT


# --------------------------------------------------------------------------- #
# CancelScope — client (C) signal
# --------------------------------------------------------------------------- #

def test_scope_client_cancellation_is_observable() -> None:
    flag = {"stop": False}
    scope = CancelScope(client_cancelled=lambda: flag["stop"])

    assert scope.should_stop() is False

    flag["stop"] = True
    assert scope.should_stop() is True
    assert scope.reason() is CancelReason.CLIENT
    with pytest.raises(ScopeCancelled) as excinfo:
        scope.check()
    assert excinfo.value.reason is CancelReason.CLIENT


# --------------------------------------------------------------------------- #
# CancelScope — host (H) signal
# --------------------------------------------------------------------------- #

def test_scope_host_stopping_is_observable() -> None:
    stopping = {"v": False}
    scope = CancelScope(host_stopping=lambda: stopping["v"])

    assert scope.should_stop() is False

    stopping["v"] = True
    assert scope.reason() is CancelReason.HOST
    with pytest.raises(ScopeCancelled) as excinfo:
        scope.check()
    assert excinfo.value.reason is CancelReason.HOST


# --------------------------------------------------------------------------- #
# CancelScope — precedence when multiple signals assert at once
# --------------------------------------------------------------------------- #

def test_client_outranks_host_and_timeout() -> None:
    scope = CancelScope(
        Deadline.after(1, now=0.0),
        client_cancelled=lambda: True,
        host_stopping=lambda: True,
    )

    assert scope.reason(now=100.0) is CancelReason.CLIENT


def test_host_outranks_timeout() -> None:
    scope = CancelScope(
        Deadline.after(1, now=0.0),
        host_stopping=lambda: True,
    )

    assert scope.reason(now=100.0) is CancelReason.HOST


# --------------------------------------------------------------------------- #
# CancelScope — the native-cancel grace latch
# --------------------------------------------------------------------------- #

def test_mark_fired_latches_first_instant_only() -> None:
    scope = CancelScope()

    assert scope.fired_at is None
    scope.mark_fired(now=42.0)
    assert scope.fired_at == 42.0
    scope.mark_fired(now=99.0)  # idempotent: keeps the first firing instant
    assert scope.fired_at == 42.0


def test_mark_fired_does_not_by_itself_force_stop() -> None:
    # Firing the native cancel latch records the instant (for the runtime grace
    # window) but is not itself one of the three should_stop signals.
    scope = CancelScope()
    scope.mark_fired(now=1.0)

    assert scope.should_stop(now=2.0) is False
    assert scope.reason(now=2.0) is None


# --------------------------------------------------------------------------- #
# ScopeCancelled carries its reason
# --------------------------------------------------------------------------- #

def test_scope_cancelled_message_defaults_to_reason() -> None:
    err = ScopeCancelled(CancelReason.TIMEOUT)

    assert err.reason is CancelReason.TIMEOUT
    assert str(err) == "timeout"

    custom = ScopeCancelled(CancelReason.CLIENT, "client went away")
    assert custom.reason is CancelReason.CLIENT
    assert str(custom) == "client went away"
