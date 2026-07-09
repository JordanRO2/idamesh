"""Shared catalog helper: run a use-case on the kernel thread, failures as errors.

Every Phase-1 tool marshals the *whole* use-case onto the kernel thread through
the injected :class:`~idamesh.domain.ports.execution.MainThreadExecutor`, then
translates any domain- or adapter-level failure into a
:class:`~idamesh.interface.mcp.engine.ToolError`. The engine renders a
``ToolError`` as an ``isError`` tool result, so an unresolved address or an
unavailable decompiler comes back as a clean per-call failure rather than a
JSON-RPC protocol fault.
"""

from __future__ import annotations

from typing import Callable, TypeVar

from idamesh.domain.ports.execution import MainThreadExecutor
from idamesh.interface.mcp.engine import ToolError

T = TypeVar("T")


def run_use_case(executor: MainThreadExecutor, job: Callable[[], T]) -> T:
    """Run ``job`` on the kernel thread; re-raise failures as ``ToolError``."""
    try:
        return executor.run(job)
    except ToolError:
        raise
    except Exception as exc:  # noqa: BLE001 — surfaced to the client as isError
        raise ToolError(str(exc)) from exc


def run_mutation(executor: MainThreadExecutor, job: Callable[[], T]) -> T:
    """Run a *mutating* ``job`` on the kernel thread with write affinity.

    The write path for the Phase-3 mutation tools (``rename`` / ``set_comment`` /
    ``set_type``). Identical marshalling to :func:`run_use_case` — the executor's
    ``run`` already defaults to ``write=True``, so the GUI backend takes the
    ``MFF_WRITE`` slot and the headless backend runs inline on the database-owning
    thread — but the write intent is passed explicitly and named at the call site,
    so a reader can see at a glance that an adapter's SDK *writes* inside ``job``
    are correctly serialized against the kernel. A domain- or SDK-level failure
    (bad name, unparsable type, out-of-function address) becomes a ``ToolError``,
    which the engine renders as an ``isError`` result rather than a crash.
    """
    try:
        return executor.run(job, write=True)
    except ToolError:
        raise
    except Exception as exc:  # noqa: BLE001 — surfaced to the client as isError
        raise ToolError(str(exc)) from exc
