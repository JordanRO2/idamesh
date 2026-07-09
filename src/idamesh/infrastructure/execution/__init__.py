"""IDA-free execution adapters.

Holds :class:`~idamesh.infrastructure.execution.inline.InlineExecutor`, the
main-thread executor for the single-threaded headless worker, where the request
handler already *is* the kernel thread so no marshaling is needed. The GUI
counterpart (``ExecuteSyncExecutor``, which touches the SDK) lives under
``infrastructure/ida`` instead.
"""

from __future__ import annotations

from idamesh.infrastructure.execution.inline import InlineExecutor

__all__ = ["InlineExecutor"]
