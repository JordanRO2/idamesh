"""The main-thread execution port.

IDA's kernel is affine to one thread; :class:`MainThreadExecutor` is the outbound
port through which the application runs a zero-argument *job* on that thread and
receives its value (or has its exception re-raised). The GUI adapter marshals via
``execute_sync``; the headless adapter runs inline because the request handler
already *is* the kernel thread. Per canonical decision §0, this is the
``MainThreadExecutor`` port (a.k.a. the scheduler / unit-of-work seam).
"""

from __future__ import annotations

from typing import Callable, Protocol, TypeVar

T = TypeVar("T")


class MainThreadExecutor(Protocol):
    """Runs a job on the kernel thread, blocking until it completes."""

    def run(self, job: Callable[[], T], *, write: bool = True) -> T:
        """Execute ``job`` on the kernel thread and return its result.

        ``write`` requests exclusive write affinity (the shipped default; see the
        execution-runtime design for why reads are treated as writes). The job's
        exception, if any, propagates to the caller with its traceback intact.
        """
        ...

    def on_kernel_thread(self) -> bool:
        """``True`` when the calling thread is already the kernel thread."""
        ...
