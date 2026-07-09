"""ExecuteSyncExecutor batch-mode regression (headless; fake idc/ida_kernwin).

The GUI executor must run every kernel job under ``idc.batch(1)`` and restore the
previous batch state afterward, on BOTH the inline (already-on-kernel-thread) and
the marshalled (execute_sync) paths. Without batch mode, driving the decompiler
from a network-thread-marshalled execute_sync while a pseudocode view is open
races the live UI's microcode and IDA raises INTERR 52813. This locks the fix in
without needing a live IDA.
"""

from __future__ import annotations

import sys
import threading
import types

import pytest

from idamesh.infrastructure.ida.execute_sync import ExecuteSyncExecutor


class _FakeIdc:
    def __init__(self) -> None:
        self.state = 0
        self.calls: list[int] = []

    def batch(self, value: int) -> int:
        self.calls.append(value)
        prev = self.state
        self.state = value
        return prev


class _FakeKernwin:
    MFF_WRITE = 1
    MFF_READ = 0

    def __init__(self, *, main_thread: bool) -> None:
        self._main = main_thread
        self.executed = 0

    def is_main_thread(self) -> bool:
        return self._main

    def execute_sync(self, fn, flags):  # noqa: ANN001
        self.executed += 1
        self._flags = flags
        return fn()


@pytest.fixture
def fake_idc(monkeypatch):
    idc = _FakeIdc()
    monkeypatch.setitem(sys.modules, "idc", types.SimpleNamespace(batch=idc.batch))
    return idc


def test_marshalled_path_wraps_job_in_batch_mode(monkeypatch, fake_idc):
    kernwin = _FakeKernwin(main_thread=False)
    monkeypatch.setitem(sys.modules, "ida_kernwin", kernwin)

    seen_batch_during_job: list[int] = []

    def job():
        seen_batch_during_job.append(fake_idc.state)  # batch is ON here
        return "ok"

    result = ExecuteSyncExecutor().run(job)

    assert result == "ok"
    assert kernwin.executed == 1  # went through execute_sync (not inline)
    assert kernwin._flags == kernwin.MFF_WRITE
    assert seen_batch_during_job == [1]  # job ran with batch(1) active
    assert fake_idc.calls == [1, 0]  # enabled, then restored to the prior state
    assert fake_idc.state == 0


def test_inline_path_also_batches(monkeypatch, fake_idc):
    kernwin = _FakeKernwin(main_thread=True)
    monkeypatch.setitem(sys.modules, "ida_kernwin", kernwin)

    result = ExecuteSyncExecutor().run(lambda: 42)

    assert result == 42
    assert kernwin.executed == 0  # ran inline, no execute_sync
    assert fake_idc.calls == [1, 0]  # still batched + restored
    assert fake_idc.state == 0


def test_batch_restored_even_when_job_raises(monkeypatch, fake_idc):
    kernwin = _FakeKernwin(main_thread=False)
    monkeypatch.setitem(sys.modules, "ida_kernwin", kernwin)

    def boom():
        raise ValueError("kaboom")

    with pytest.raises(ValueError, match="kaboom"):
        ExecuteSyncExecutor().run(boom)

    assert fake_idc.calls == [1, 0]  # restored despite the exception
    assert fake_idc.state == 0


# --- on_kernel_thread(): pinned ident (Fix A) + repaired probe (Fix B) --------


def test_on_kernel_thread_uses_pinned_ident_when_provided():
    # The GUI plugin pins the kernel-thread ident at load so affinity is a
    # deterministic comparison, never the fragile is_main_thread() probe.
    here = ExecuteSyncExecutor(kernel_thread_id=threading.get_ident())
    assert here.on_kernel_thread() is True

    elsewhere = ExecuteSyncExecutor(kernel_thread_id=-1)  # some other thread's id
    assert elsewhere.on_kernel_thread() is False


def test_probe_prefers_ida_pro_is_main_thread(monkeypatch):
    # Unpinned executor falls back to a probe; is_main_thread lives in ida_pro.
    monkeypatch.setitem(sys.modules, "ida_pro", types.SimpleNamespace(is_main_thread=lambda: True))
    assert ExecuteSyncExecutor().on_kernel_thread() is True

    monkeypatch.setitem(sys.modules, "ida_pro", types.SimpleNamespace(is_main_thread=lambda: False))
    assert ExecuteSyncExecutor().on_kernel_thread() is False


def test_probe_falls_back_to_ida_kernwin_when_ida_pro_lacks_symbol(monkeypatch):
    # ida_pro present but without is_main_thread -> try ida_kernwin (cross-version).
    monkeypatch.setitem(sys.modules, "ida_pro", types.SimpleNamespace())
    monkeypatch.setitem(sys.modules, "ida_kernwin", types.SimpleNamespace(is_main_thread=lambda: True))
    assert ExecuteSyncExecutor().on_kernel_thread() is True


def test_probe_degrades_to_false_when_symbol_absent(monkeypatch):
    # Neither module exposes is_main_thread -> safe default: marshal, don't run
    # SDK work off-thread.
    monkeypatch.setitem(sys.modules, "ida_pro", types.SimpleNamespace())
    monkeypatch.setitem(sys.modules, "ida_kernwin", types.SimpleNamespace())
    assert ExecuteSyncExecutor().on_kernel_thread() is False
