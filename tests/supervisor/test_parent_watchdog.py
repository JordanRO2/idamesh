"""Unit tests for the parent-pid watchdog (idapro-free).

The watchdog's whole job is one decision — *is the process that spawned me still
alive?* — and one action — *fire a clean-shutdown callback exactly once when it is
not*. These tests fake the liveness check so the alive/dead decision and the
callback wiring are exercised deterministically with no real second process, plus
one live self-check that :func:`parent_alive` reports this very process alive and a
never-allocated pid dead.
"""

from __future__ import annotations

import os
import threading

from idamesh.infrastructure.process.parent_watchdog import (
    ParentWatchdog,
    parent_alive,
)


def test_parent_alive_true_for_self():
    # This test process is, definitionally, alive.
    assert parent_alive(os.getpid()) is True


def test_parent_alive_false_for_dead_pid():
    # A pid that was never a real, currently-running process reads as dead.
    # (2**31-1 is far above any live pid on the platforms we target.)
    assert parent_alive(2_147_483_647) is False


def test_parent_alive_treats_nonpositive_as_alive():
    # A bogus/absent parent id must never trigger a shutdown.
    assert parent_alive(0) is True
    assert parent_alive(-1) is True


def test_watchdog_fires_callback_when_parent_dies():
    fired = threading.Event()
    # Alive on the first poll, gone on the second — the watchdog must then fire.
    calls = {"n": 0}

    def alive_check(_pid: int) -> bool:
        calls["n"] += 1
        return calls["n"] < 2

    wd = ParentWatchdog(
        4321,
        on_parent_dead=fired.set,
        poll_interval=0.01,
        alive_check=alive_check,
    )
    wd.start()
    assert fired.wait(timeout=2.0), "watchdog should fire once the parent is gone"
    wd.stop()


def test_watchdog_does_not_fire_while_parent_alive():
    fired = threading.Event()
    wd = ParentWatchdog(
        4321,
        on_parent_dead=fired.set,
        poll_interval=0.01,
        alive_check=lambda _pid: True,  # parent stays alive forever
    )
    wd.start()
    # Give it several poll intervals; the callback must stay unfired.
    assert not fired.wait(timeout=0.2)
    wd.stop()


def test_watchdog_stop_promptly_ends_the_watch():
    fired = threading.Event()
    # Parent stays alive, so the watchdog sits in its (long) interval wait; stop()
    # must unblock that wait immediately and end the thread without ever firing.
    wd = ParentWatchdog(
        4321,
        on_parent_dead=fired.set,
        poll_interval=30.0,
        alive_check=lambda _pid: True,
    )
    wd.start()
    wd.stop()
    assert not fired.wait(timeout=0.2)
    assert wd._thread is not None and not wd._thread.is_alive()


def test_watchdog_fires_immediately_when_parent_already_dead():
    fired = threading.Event()
    wd = ParentWatchdog(
        4321,
        on_parent_dead=fired.set,
        poll_interval=30.0,  # long interval; must not wait for it
        alive_check=lambda _pid: False,
    )
    wd.start()
    assert fired.wait(timeout=2.0)
    wd.stop()
