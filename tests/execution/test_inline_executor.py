"""Tests for :class:`InlineExecutor` — the no-marshal main-thread executor.

The headless worker runs single-threaded on the thread that opened the database,
so ``run`` invokes the job directly on the calling thread. We assert three
things: the value round-trips, an exception raised inside the job propagates with
its *original* traceback (there is no cross-thread mailbox to flatten it), and
the kernel-thread probe reflects the thread that constructed the executor.
"""

from __future__ import annotations

import threading
import traceback

import pytest

from idamesh.infrastructure.execution import InlineExecutor
from idamesh.infrastructure.execution.inline import InlineExecutor as DirectImport


def test_run_returns_job_value_by_identity() -> None:
    executor = InlineExecutor()
    sentinel = object()

    assert executor.run(lambda: sentinel) is sentinel


def test_run_returns_falsey_values_verbatim() -> None:
    executor = InlineExecutor()

    assert executor.run(lambda: 0) == 0
    assert executor.run(lambda: "") == ""
    assert executor.run(lambda: None) is None


def test_write_flag_is_a_noop_for_inline() -> None:
    executor = InlineExecutor()

    assert executor.run(lambda: 42, write=True) == 42
    assert executor.run(lambda: 42, write=False) == 42


def test_run_is_synchronous_and_single_shot() -> None:
    executor = InlineExecutor()
    calls: list[int] = []

    def job() -> str:
        calls.append(1)
        return "done"

    result = executor.run(job)

    assert result == "done"
    assert calls == [1]  # invoked exactly once, inline


def test_exception_propagates_with_original_traceback() -> None:
    executor = InlineExecutor()

    def failing_job() -> None:
        raise ValueError("kaboom from the far side")

    with pytest.raises(ValueError) as excinfo:
        executor.run(failing_job)

    assert str(excinfo.value) == "kaboom from the far side"
    rendered = "".join(traceback.format_tb(excinfo.value.__traceback__))
    # The job's own frame must survive in the traceback — proof there was no
    # cross-thread re-raise that would have severed it.
    assert "failing_job" in rendered


def test_base_exception_also_propagates() -> None:
    executor = InlineExecutor()

    def job() -> None:
        raise KeyboardInterrupt()

    with pytest.raises(KeyboardInterrupt):
        executor.run(job)


def test_on_kernel_thread_true_on_constructing_thread() -> None:
    executor = InlineExecutor()

    assert executor.on_kernel_thread() is True


def test_on_kernel_thread_false_from_another_thread() -> None:
    executor = InlineExecutor()
    observed: list[bool] = []

    def probe() -> None:
        observed.append(executor.on_kernel_thread())

    worker = threading.Thread(target=probe)
    worker.start()
    worker.join()

    assert observed == [False]


def test_explicit_kernel_thread_id_is_honored() -> None:
    # A foreign id that is not this thread's makes the probe report "off-kernel".
    foreign = threading.get_ident() + 1
    executor = InlineExecutor(kernel_thread_id=foreign)

    assert executor.on_kernel_thread() is False
    # ...yet run still executes inline regardless of the probe.
    assert executor.run(lambda: "still runs") == "still runs"


def test_public_and_module_import_are_same_class() -> None:
    assert InlineExecutor is DirectImport
