"""``InlineExecutor`` — the no-marshal main-thread executor (IDA-free).

The headless worker serves single-threaded on the process main thread, which is
the same thread that opened the database. So :meth:`run` always runs the job
inline: no ``execute_sync`` hop, no queue, no cross-thread latency. Implements
the :class:`~idamesh.domain.ports.execution.MainThreadExecutor` port. This module
imports no IDA SDK, so it is unit-testable off-host.
"""

from __future__ import annotations

import threading
from typing import Callable, Optional, TypeVar

T = TypeVar("T")


class InlineExecutor:
    """Runs kernel jobs inline on the calling (kernel) thread."""

    def __init__(self, *, kernel_thread_id: Optional[int] = None) -> None:
        """Capture the kernel thread id (defaults to the constructing thread)."""
        self._kernel_thread_id = (
            kernel_thread_id if kernel_thread_id is not None else threading.get_ident()
        )

    def run(self, job: Callable[[], T], *, write: bool = True) -> T:
        """Execute ``job`` immediately and return its result.

        Because the headless worker already runs on the kernel thread, the job is
        invoked directly on the calling thread — no ``execute_sync`` hop, no
        result queue, no cross-thread marshaling. The ``write`` flag (write
        affinity, relevant only to the marshaling GUI executor) is therefore a
        no-op here. Any exception the job raises propagates unchanged, with its
        original traceback intact, since it travels the ordinary call stack rather
        than a cross-thread mailbox.
        """
        return job()

    def on_kernel_thread(self) -> bool:
        """``True`` when called from the captured kernel thread."""
        return threading.get_ident() == self._kernel_thread_id
