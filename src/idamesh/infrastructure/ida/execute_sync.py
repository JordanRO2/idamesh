"""``ExecuteSyncExecutor`` — the GUI main-thread executor.

Implements the :class:`~idamesh.domain.ports.execution.MainThreadExecutor` port
for the resident GUI plugin: when called from a network thread it marshals the
job onto IDA's kernel thread via ``ida_kernwin.execute_sync(thunk, MFF_WRITE)``,
ferrying the result (or exception, traceback intact) back through a one-shot
mailbox; when already on the kernel thread it runs inline. The SDK import is lazy
(inside the methods) so this module imports cleanly without IDA present.

Write affinity is uniform (``MFF_WRITE``): decompilation lazily writes to the
database, so there is no safe read-only fast path — see the execution-runtime
design for the rationale.
"""

from __future__ import annotations

import threading
from typing import Callable, Optional, TypeVar

T = TypeVar("T")


class ExecuteSyncExecutor:
    """Marshals kernel jobs onto IDA's UI thread from arbitrary threads."""

    def __init__(self, *, kernel_thread_id: Optional[int] = None) -> None:
        self._kernel_thread_id = kernel_thread_id

    def run(self, job: Callable[[], T], *, write: bool = True) -> T:
        """Run ``job`` on the kernel thread (inline if already there).

        The job runs under IDA batch mode (``idc.batch(1)``). In the resident GUI
        plugin this is essential, not cosmetic: without it, running the decompiler
        (or other analysis) from a network-thread-marshalled ``execute_sync`` while
        the user has a pseudocode/graph view open lets the scripted call fight the
        live UI's microcode state — which surfaces as ``INTERR 52813`` /
        "deleted stale microcode". Batch mode suppresses that UI interaction for
        the duration and is restored afterward.
        """
        if self.on_kernel_thread():
            return self._batched(job)

        import ida_kernwin

        flags = ida_kernwin.MFF_WRITE if write else ida_kernwin.MFF_READ
        box: dict[str, object] = {}

        def thunk() -> int:
            try:
                box["value"] = self._batched(job)
            except BaseException as exc:  # noqa: BLE001 — re-raised on the caller
                box["error"] = exc
            return 1

        ida_kernwin.execute_sync(thunk, flags)

        if "error" in box:
            raise box["error"]  # type: ignore[misc]
        return box["value"]  # type: ignore[return-value]

    @staticmethod
    def _batched(job: Callable[[], T]) -> T:
        """Run ``job`` on the kernel thread under IDA batch mode, restoring the
        previous batch state afterward (nesting-safe)."""
        import idc

        old_batch = idc.batch(1)
        try:
            return job()
        finally:
            idc.batch(old_batch)

    def on_kernel_thread(self) -> bool:
        """``True`` when the caller is IDA's kernel (UI) thread.

        The GUI plugin pins ``kernel_thread_id`` at load (on the UI thread), so
        this is normally a deterministic ident comparison. The probe fallback is
        only for a bare, unpinned executor: ``is_main_thread`` lives in ``ida_pro``
        (not ``ida_kernwin``) in current builds, with the other name tried as a
        cross-version fallback. A genuinely missing symbol degrades safely to
        "not on the kernel thread", so callers marshal via ``execute_sync`` rather
        than run SDK work off-thread.
        """
        if self._kernel_thread_id is not None:
            return threading.get_ident() == self._kernel_thread_id
        for module_name in ("ida_pro", "ida_kernwin"):
            try:
                module = __import__(module_name)
                return bool(module.is_main_thread())
            except Exception:
                continue
        return False
